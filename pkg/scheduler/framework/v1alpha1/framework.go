/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"context"
	"fmt"
	"reflect"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
	"k8s.io/kubernetes/pkg/scheduler/apis/config"
	schedulernodeinfo "k8s.io/kubernetes/pkg/scheduler/nodeinfo"
	schedutil "k8s.io/kubernetes/pkg/scheduler/util"
)

// framework is the component responsible for initializing and running scheduler
// plugins.
type framework struct {
	registry              Registry
	nodeInfoSnapshot      *schedulernodeinfo.Snapshot
	waitingPods           *waitingPodsMap
	pluginNameToWeightMap map[string]int
	queueSortPlugins      []QueueSortPlugin
	preFilterPlugins      []PreFilterPlugin
	filterPlugins         []FilterPlugin
	postFilterPlugins     []PostFilterPlugin
	scorePlugins          []ScorePlugin
	reservePlugins        []ReservePlugin
	preBindPlugins        []PreBindPlugin
	bindPlugins           []BindPlugin
	postBindPlugins       []PostBindPlugin
	unreservePlugins      []UnreservePlugin
	permitPlugins         []PermitPlugin
}

const (
	// Specifies the maximum timeout a permit plugin can return.
	maxTimeout time.Duration = 15 * time.Minute
)

var _ = Framework(&framework{})

// NewFramework initializes plugins given the configuration and the registry.
func NewFramework(r Registry, plugins *config.Plugins, args []config.PluginConfig) (Framework, error) {
	f := &framework{
		registry:              r,
		nodeInfoSnapshot:      schedulernodeinfo.NewSnapshot(),
		pluginNameToWeightMap: make(map[string]int),
		waitingPods:           newWaitingPodsMap(),
	}
	if plugins == nil {
		return f, nil
	}

	// get needed plugins from config
	pg := pluginsNeeded(plugins)
	if len(pg) == 0 {
		return f, nil
	}

	pluginConfig := pluginNameToConfig(args)
	pluginsMap := make(map[string]Plugin)
	for name, factory := range r {
		// initialize only needed plugins
		if _, ok := pg[name]; !ok {
			continue
		}

		// find the config args of a plugin
		pc := pluginConfig[name]

		p, err := factory(pc, f)
		if err != nil {
			return nil, fmt.Errorf("error initializing plugin %q: %v", name, err)
		}
		pluginsMap[name] = p

		// A weight of zero is not permitted, plugins can be disabled explicitly
		// when configured.
		f.pluginNameToWeightMap[name] = int(pg[name].Weight)
		if f.pluginNameToWeightMap[name] == 0 {
			f.pluginNameToWeightMap[name] = 1
		}
	}

	if err := updatePluginList(reflect.ValueOf(&f.preFilterPlugins), plugins.PreFilter, reflect.TypeOf((*PreFilterPlugin)(nil)), pluginsMap); err != nil {
		return nil, err
	}

	if err := updatePluginList(reflect.ValueOf(&f.filterPlugins), plugins.Filter, reflect.TypeOf((*FilterPlugin)(nil)), pluginsMap); err != nil {
		return nil, err
	}

	if err := updatePluginList(reflect.ValueOf(&f.reservePlugins), plugins.Reserve, reflect.TypeOf((*ReservePlugin)(nil)), pluginsMap); err != nil {
		return nil, err
	}

	if err := updatePluginList(reflect.ValueOf(&f.postFilterPlugins), plugins.PostFilter, reflect.TypeOf((*PostFilterPlugin)(nil)), pluginsMap); err != nil {
		return nil, err
	}

	if err := updatePluginList(reflect.ValueOf(&f.scorePlugins), plugins.Score, reflect.TypeOf((*ScorePlugin)(nil)), pluginsMap); err != nil {
		return nil, err
	}

	if err := updatePluginList(reflect.ValueOf(&f.preBindPlugins), plugins.PreBind, reflect.TypeOf((*PreBindPlugin)(nil)), pluginsMap); err != nil {
		return nil, err
	}

	if err := updatePluginList(reflect.ValueOf(&f.bindPlugins), plugins.Bind, reflect.TypeOf((*BindPlugin)(nil)), pluginsMap); err != nil {
		return nil, err
	}

	if err := updatePluginList(reflect.ValueOf(&f.postBindPlugins), plugins.PostBind, reflect.TypeOf((*PostBindPlugin)(nil)), pluginsMap); err != nil {
		return nil, err
	}

	if err := updatePluginList(reflect.ValueOf(&f.unreservePlugins), plugins.Unreserve, reflect.TypeOf((*UnreservePlugin)(nil)), pluginsMap); err != nil {
		return nil, err
	}

	if err := updatePluginList(reflect.ValueOf(&f.permitPlugins), plugins.Permit, reflect.TypeOf((*PermitPlugin)(nil)), pluginsMap); err != nil {
		return nil, err
	}

	if err := updatePluginList(reflect.ValueOf(&f.queueSortPlugins), plugins.QueueSort, reflect.TypeOf((*QueueSortPlugin)(nil)), pluginsMap); err != nil {
		return nil, err
	}

	for _, scorePlugin := range f.scorePlugins {
		if f.pluginNameToWeightMap[scorePlugin.Name()] == 0 {
			return nil, fmt.Errorf("score plugin %q is not configured with weight", scorePlugin.Name())
		}
	}

	if len(f.queueSortPlugins) > 1 {
		return nil, fmt.Errorf("only one queue sort plugin can be enabled")
	}

	return f, nil
}

func updatePluginList(pluginList reflect.Value, pluginSet *config.PluginSet, pluginType reflect.Type, pluginsMap map[string]Plugin) error {
	if pluginSet == nil {
		return nil
	}

	plugins := pluginList.Elem()
	pluginType = pluginType.Elem()
	set := sets.NewString()
	for _, ep := range pluginSet.Enabled {
		pg, ok := pluginsMap[ep.Name]
		if !ok {
			return fmt.Errorf("%s %q does not exist", pluginType.String(), ep.Name)
		}

		if !reflect.TypeOf(pg).Implements(pluginType) {
			return fmt.Errorf("plugin %q does not extend %s plugin", ep.Name, pluginType.String())
		}

		if set.Has(ep.Name) {
			return fmt.Errorf("plugin %q already registered as %q", ep.Name, pluginType.String())
		}

		set.Insert(ep.Name)

		newPlugins := reflect.Append(plugins, reflect.ValueOf(pg))
		plugins.Set(newPlugins)
	}
	return nil
}

// QueueSortFunc returns the function to sort pods in scheduling queue
func (f *framework) QueueSortFunc() LessFunc {
	if len(f.queueSortPlugins) == 0 {
		return nil
	}

	// Only one QueueSort plugin can be enabled.
	return f.queueSortPlugins[0].Less
}

// RunPreFilterPlugins runs the set of configured PreFilter plugins. It returns
// *Status and its code is set to non-success if any of the plugins returns
// anything but Success. If a non-success status is returned, then the scheduling
// cycle is aborted.
func (f *framework) RunPreFilterPlugins(
	pc *PluginContext, pod *v1.Pod) *Status {
	for _, pl := range f.preFilterPlugins {
		status := pl.PreFilter(pc, pod)
		if !status.IsSuccess() {
			if status.IsUnschedulable() {
				msg := fmt.Sprintf("rejected by %q at prefilter: %v", pl.Name(), status.Message())
				klog.V(4).Infof(msg)
				return NewStatus(status.Code(), msg)
			}
			msg := fmt.Sprintf("error while running %q prefilter plugin for pod %q: %v", pl.Name(), pod.Name, status.Message())
			klog.Error(msg)
			return NewStatus(Error, msg)
		}
	}

	return nil
}

// RunPreFilterExtensionAddPod calls the AddPod interface for the set of configured
// PreFilter plugins. It returns directly if any of the plugins return any
// status other than Success.
func (f *framework) RunPreFilterExtensionAddPod(pc *PluginContext, podToSchedule *v1.Pod,
	podToAdd *v1.Pod, nodeInfo *schedulernodeinfo.NodeInfo) *Status {
	for _, pl := range f.preFilterPlugins {
		if pl.Extensions() == nil {
			continue
		}
		if status := pl.Extensions().AddPod(pc, podToSchedule, podToAdd, nodeInfo); !status.IsSuccess() {
			msg := fmt.Sprintf("error while running AddPod for plugin %q while scheduling pod %q: %v",
				pl.Name(), podToSchedule.Name, status.Message())
			klog.Error(msg)
			return NewStatus(Error, msg)
		}
	}

	return nil
}

// RunPreFilterExtensionRemovePod calls the RemovePod interface for the set of configured
// PreFilter plugins. It returns directly if any of the plugins return any
// status other than Success.
func (f *framework) RunPreFilterExtensionRemovePod(pc *PluginContext, podToSchedule *v1.Pod,
	podToRemove *v1.Pod, nodeInfo *schedulernodeinfo.NodeInfo) *Status {
	for _, pl := range f.preFilterPlugins {
		if pl.Extensions() == nil {
			continue
		}
		if status := pl.Extensions().RemovePod(pc, podToSchedule, podToRemove, nodeInfo); !status.IsSuccess() {
			msg := fmt.Sprintf("error while running RemovePod for plugin %q while scheduling pod %q: %v",
				pl.Name(), podToSchedule.Name, status.Message())
			klog.Error(msg)
			return NewStatus(Error, msg)
		}
	}

	return nil
}

// RunFilterPlugins runs the set of configured Filter plugins for pod on
// the given node. If any of these plugins doesn't return "Success", the
// given node is not suitable for running pod.
// Meanwhile, the failure message and status are set for the given node.
func (f *framework) RunFilterPlugins(pc *PluginContext,
	pod *v1.Pod, nodeInfo *schedulernodeinfo.NodeInfo) *Status {
	for _, pl := range f.filterPlugins {
		status := pl.Filter(pc, pod, nodeInfo)
		if !status.IsSuccess() {
			if !status.IsUnschedulable() {
				errMsg := fmt.Sprintf("error while running %q filter plugin for pod %q: %v",
					pl.Name(), pod.Name, status.Message())
				klog.Error(errMsg)
				return NewStatus(Error, errMsg)
			}
			return status
		}
	}

	return nil
}

// RunPostFilterPlugins runs the set of configured post-filter plugins. If any
// of these plugins returns any status other than "Success", the given node is
// rejected. The filteredNodeStatuses is the set of filtered nodes and their statuses.
func (f *framework) RunPostFilterPlugins(
	pc *PluginContext,
	pod *v1.Pod,
	nodes []*v1.Node,
	filteredNodesStatuses NodeToStatusMap,
) *Status {
	for _, pl := range f.postFilterPlugins {
		status := pl.PostFilter(pc, pod, nodes, filteredNodesStatuses)
		if !status.IsSuccess() {
			msg := fmt.Sprintf("error while running %q postfilter plugin for pod %q: %v", pl.Name(), pod.Name, status.Message())
			klog.Error(msg)
			return NewStatus(Error, msg)
		}
	}

	return nil
}

// RunScorePlugins runs the set of configured scoring plugins. It returns a list that
// stores for each scoring plugin name the corresponding NodeScoreList(s).
// It also returns *Status, which is set to non-success if any of the plugins returns
// a non-success status.
func (f *framework) RunScorePlugins(pc *PluginContext, pod *v1.Pod, nodes []*v1.Node) (PluginToNodeScores, *Status) {
	pluginToNodeScores := make(PluginToNodeScores, len(f.scorePlugins))
	for _, pl := range f.scorePlugins {
		pluginToNodeScores[pl.Name()] = make(NodeScoreList, len(nodes))
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := schedutil.NewErrorChannel()

	// Run Score method for each node in parallel.
	workqueue.ParallelizeUntil(ctx, 16, len(nodes), func(index int) {
		for _, pl := range f.scorePlugins {
			nodeName := nodes[index].Name
			score, status := pl.Score(pc, pod, nodeName)
			if !status.IsSuccess() {
				errCh.SendErrorWithCancel(fmt.Errorf(status.Message()), cancel)
				return
			}
			pluginToNodeScores[pl.Name()][index] = NodeScore{
				Name:  nodeName,
				Score: int64(score),
			}
		}
	})
	if err := errCh.ReceiveError(); err != nil {
		msg := fmt.Sprintf("error while running score plugin for pod %q: %v", pod.Name, err)
		klog.Error(msg)
		return nil, NewStatus(Error, msg)
	}

	// Run NormalizeScore method for each ScorePlugin in parallel.
	workqueue.ParallelizeUntil(ctx, 16, len(f.scorePlugins), func(index int) {
		pl := f.scorePlugins[index]
		nodeScoreList := pluginToNodeScores[pl.Name()]
		if pl.Extensions() == nil {
			return
		}
		if status := pl.Extensions().NormalizeScore(pc, pod, nodeScoreList); !status.IsSuccess() {
			err := fmt.Errorf("normalize score plugin %q failed with error %v", pl.Name(), status.Message())
			errCh.SendErrorWithCancel(err, cancel)
			return
		}
	})
	if err := errCh.ReceiveError(); err != nil {
		msg := fmt.Sprintf("error while running normalize score plugin for pod %q: %v", pod.Name, err)
		klog.Error(msg)
		return nil, NewStatus(Error, msg)
	}

	// Apply score defaultWeights for each ScorePlugin in parallel.
	workqueue.ParallelizeUntil(ctx, 16, len(f.scorePlugins), func(index int) {
		pl := f.scorePlugins[index]
		// Score plugins' weight has been checked when they are initialized.
		weight := f.pluginNameToWeightMap[pl.Name()]
		nodeScoreList := pluginToNodeScores[pl.Name()]

		for i, nodeScore := range nodeScoreList {
			// return error if score plugin returns invalid score.
			if nodeScore.Score > int64(MaxNodeScore) || nodeScore.Score < int64(MinNodeScore) {
				err := fmt.Errorf("score plugin %q returns an invalid score %v, it should in the range of [%v, %v] after normalizing", pl.Name(), nodeScore.Score, MinNodeScore, MaxNodeScore)
				errCh.SendErrorWithCancel(err, cancel)
				return
			}
			nodeScoreList[i].Score = nodeScore.Score * int64(weight)
		}
	})
	if err := errCh.ReceiveError(); err != nil {
		msg := fmt.Sprintf("error while applying score defaultWeights for pod %q: %v", pod.Name, err)
		klog.Error(msg)
		return nil, NewStatus(Error, msg)
	}

	return pluginToNodeScores, nil
}

// RunPreBindPlugins runs the set of configured prebind plugins. It returns a
// failure (bool) if any of the plugins returns an error. It also returns an
// error containing the rejection message or the error occurred in the plugin.
func (f *framework) RunPreBindPlugins(
	pc *PluginContext, pod *v1.Pod, nodeName string) *Status {
	for _, pl := range f.preBindPlugins {
		status := pl.PreBind(pc, pod, nodeName)
		if !status.IsSuccess() {
			msg := fmt.Sprintf("error while running %q prebind plugin for pod %q: %v", pl.Name(), pod.Name, status.Message())
			klog.Error(msg)
			return NewStatus(Error, msg)
		}
	}
	return nil
}

// RunBindPlugins runs the set of configured bind plugins until one returns a non `Skip` status.
func (f *framework) RunBindPlugins(pc *PluginContext, pod *v1.Pod, nodeName string) *Status {
	if len(f.bindPlugins) == 0 {
		return NewStatus(Skip, "")
	}
	var status *Status
	for _, bp := range f.bindPlugins {
		status = bp.Bind(pc, pod, nodeName)
		if status != nil && status.Code() == Skip {
			continue
		}
		if !status.IsSuccess() {
			msg := fmt.Sprintf("bind plugin %q failed to bind pod \"%v/%v\": %v", bp.Name(), pod.Namespace, pod.Name, status.Message())
			klog.Error(msg)
			return NewStatus(Error, msg)
		}
		return status
	}
	return status
}

// RunPostBindPlugins runs the set of configured postbind plugins.
func (f *framework) RunPostBindPlugins(
	pc *PluginContext, pod *v1.Pod, nodeName string) {
	for _, pl := range f.postBindPlugins {
		pl.PostBind(pc, pod, nodeName)
	}
}

// RunReservePlugins runs the set of configured reserve plugins. If any of these
// plugins returns an error, it does not continue running the remaining ones and
// returns the error. In such case, pod will not be scheduled.
func (f *framework) RunReservePlugins(
	pc *PluginContext, pod *v1.Pod, nodeName string) *Status {
	for _, pl := range f.reservePlugins {
		status := pl.Reserve(pc, pod, nodeName)
		if !status.IsSuccess() {
			msg := fmt.Sprintf("error while running %q reserve plugin for pod %q: %v", pl.Name(), pod.Name, status.Message())
			klog.Error(msg)
			return NewStatus(Error, msg)
		}
	}
	return nil
}

// RunUnreservePlugins runs the set of configured unreserve plugins.
func (f *framework) RunUnreservePlugins(
	pc *PluginContext, pod *v1.Pod, nodeName string) {
	for _, pl := range f.unreservePlugins {
		pl.Unreserve(pc, pod, nodeName)
	}
}

// RunPermitPlugins runs the set of configured permit plugins. If any of these
// plugins returns a status other than "Success" or "Wait", it does not continue
// running the remaining plugins and returns an error. Otherwise, if any of the
// plugins returns "Wait", then this function will block for the timeout period
// returned by the plugin, if the time expires, then it will return an error.
// Note that if multiple plugins asked to wait, then we wait for the minimum
// timeout duration.
func (f *framework) RunPermitPlugins(
	pc *PluginContext, pod *v1.Pod, nodeName string) *Status {
	timeout := maxTimeout
	statusCode := Success
	for _, pl := range f.permitPlugins {
		status, d := pl.Permit(pc, pod, nodeName)
		if !status.IsSuccess() {
			if status.IsUnschedulable() {
				msg := fmt.Sprintf("rejected by %q at permit: %v", pl.Name(), status.Message())
				klog.V(4).Infof(msg)
				return NewStatus(status.Code(), msg)
			}
			if status.Code() == Wait {
				// Use the minimum timeout duration.
				if timeout > d {
					timeout = d
				}
				statusCode = Wait
			} else {
				msg := fmt.Sprintf("error while running %q permit plugin for pod %q: %v", pl.Name(), pod.Name, status.Message())
				klog.Error(msg)
				return NewStatus(Error, msg)
			}
		}
	}

	// We now wait for the minimum duration if at least one plugin asked to
	// wait (and no plugin rejected the pod)
	if statusCode == Wait {
		w := newWaitingPod(pod)
		f.waitingPods.add(w)
		defer f.waitingPods.remove(pod.UID)
		timer := time.NewTimer(timeout)
		klog.V(4).Infof("waiting for %v for pod %q at permit", timeout, pod.Name)
		select {
		case <-timer.C:
			msg := fmt.Sprintf("pod %q rejected due to timeout after waiting %v at permit", pod.Name, timeout)
			klog.V(4).Infof(msg)
			return NewStatus(Unschedulable, msg)
		case s := <-w.s:
			if !s.IsSuccess() {
				if s.IsUnschedulable() {
					msg := fmt.Sprintf("rejected while waiting at permit: %v", s.Message())
					klog.V(4).Infof(msg)
					return NewStatus(s.Code(), msg)
				}
				msg := fmt.Sprintf("error received while waiting at permit for pod %q: %v", pod.Name, s.Message())
				klog.Error(msg)
				return NewStatus(Error, msg)
			}
		}
	}

	return nil
}

// NodeInfoSnapshot returns the latest NodeInfo snapshot. The snapshot
// is taken at the beginning of a scheduling cycle and remains unchanged until a
// pod finishes "Reserve". There is no guarantee that the information remains
// unchanged after "Reserve".
func (f *framework) NodeInfoSnapshot() *schedulernodeinfo.Snapshot {
	return f.nodeInfoSnapshot
}

// IterateOverWaitingPods acquires a read lock and iterates over the WaitingPods map.
func (f *framework) IterateOverWaitingPods(callback func(WaitingPod)) {
	f.waitingPods.iterate(callback)
}

// GetWaitingPod returns a reference to a WaitingPod given its UID.
func (f *framework) GetWaitingPod(uid types.UID) WaitingPod {
	return f.waitingPods.get(uid)
}

func pluginNameToConfig(args []config.PluginConfig) map[string]*runtime.Unknown {
	pc := make(map[string]*runtime.Unknown, 0)
	for i := range args {
		// This is needed because the type of PluginConfig.Args is not pointer type.
		p := args[i]
		pc[p.Name] = &p.Args
	}
	return pc
}

func pluginsNeeded(plugins *config.Plugins) map[string]config.Plugin {
	pgMap := make(map[string]config.Plugin, 0)

	if plugins == nil {
		return pgMap
	}

	find := func(pgs *config.PluginSet) {
		if pgs == nil {
			return
		}
		for _, pg := range pgs.Enabled {
			pgMap[pg.Name] = pg
		}
	}
	find(plugins.QueueSort)
	find(plugins.PreFilter)
	find(plugins.Filter)
	find(plugins.PostFilter)
	find(plugins.Score)
	find(plugins.Reserve)
	find(plugins.Permit)
	find(plugins.PreBind)
	find(plugins.Bind)
	find(plugins.PostBind)
	find(plugins.Unreserve)

	return pgMap
}
