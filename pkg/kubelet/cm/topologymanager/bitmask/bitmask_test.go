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

package bitmask

import (
	"reflect"
	"testing"
)

func TestNewBitMask(t *testing.T) {
	tcases := []struct {
		name         string
		bit          int
		expectedMask string
	}{
		{
			name:         "New BitMask with bit 0 set",
			bit:          0,
			expectedMask: "0000000000000000000000000000000000000000000000000000000000000001",
		},
	}
	for _, tc := range tcases {
		sm, _ := NewBitMask(0)
		if sm.String() != tc.expectedMask {
			t.Errorf("Expected mask to be %v, got %v", tc.expectedMask, sm)
		}
	}
}

func TestAdd(t *testing.T) {
	tcases := []struct {
		name         string
		firstbit     int
		secondbit    int
		expectedMask string
	}{
		{
			name:         "New BitMask with bits 0 and 1 set",
			firstbit:     0,
			secondbit:    1,
			expectedMask: "0000000000000000000000000000000000000000000000000000000000000011",
		},
	}
	for _, tc := range tcases {
		mask, _ := NewBitMask()
		mask.Add(tc.firstbit, tc.secondbit)
		if mask.String() != tc.expectedMask {
			t.Errorf("Expected mask to be %v, got %v", tc.expectedMask, mask)
		}
	}
}

func TestRemove(t *testing.T) {
	tcases := []struct {
		name           string
		firstbitset    int
		secondbitset   int
		firstbitRemove int
		expectedMask   string
	}{
		{
			name:           "Reset bit 1 BitMask to 0",
			firstbitset:    0,
			secondbitset:   1,
			firstbitRemove: 0,
			expectedMask:   "0000000000000000000000000000000000000000000000000000000000000010",
		},
	}
	for _, tc := range tcases {
		mask, _ := NewBitMask(tc.firstbitset, tc.secondbitset)
		mask.Remove(tc.firstbitRemove)
		if mask.String() != tc.expectedMask {
			t.Errorf("Expected mask to be %v, got %v", tc.expectedMask, mask)
		}
	}
}

func TestAnd(t *testing.T) {
	tcases := []struct {
		name          string
		firstMaskBit  int
		secondMaskBit int
		andMask       string
	}{
		{
			name:          "And bit masks",
			firstMaskBit:  0,
			secondMaskBit: 0,
			andMask:       "0000000000000000000000000000000000000000000000000000000000000001",
		},
	}
	for _, tc := range tcases {
		firstMask, _ := NewBitMask(tc.firstMaskBit)
		secondMask, _ := NewBitMask(tc.secondMaskBit)

		result := And(firstMask, secondMask)
		if result.String() != string(tc.andMask) {
			t.Errorf("Expected mask to be %v, got %v", tc.andMask, result)
		}

		firstMask.And(secondMask)
		if firstMask.String() != string(tc.andMask) {
			t.Errorf("Expected mask to be %v, got %v", tc.andMask, firstMask)
		}
	}
}

func TestOr(t *testing.T) {
	tcases := []struct {
		name          string
		firstMaskBit  int
		secondMaskBit int
		orMask        string
	}{
		{
			name:          "Or bit masks",
			firstMaskBit:  0,
			secondMaskBit: 1,
			orMask:        "0000000000000000000000000000000000000000000000000000000000000011",
		},
	}
	for _, tc := range tcases {
		firstMask, _ := NewBitMask(tc.firstMaskBit)
		secondMask, _ := NewBitMask(tc.secondMaskBit)

		result := Or(firstMask, secondMask)
		if result.String() != string(tc.orMask) {
			t.Errorf("Expected mask to be %v, got %v", tc.orMask, result)
		}

		firstMask.Or(secondMask)
		if firstMask.String() != string(tc.orMask) {
			t.Errorf("Expected mask to be %v, got %v", tc.orMask, firstMask)
		}
	}
}

func TestClear(t *testing.T) {
	tcases := []struct {
		name        string
		firstBit    int
		secondBit   int
		clearedMask string
	}{
		{
			name:        "Clear bit masks",
			firstBit:    0,
			secondBit:   1,
			clearedMask: "0000000000000000000000000000000000000000000000000000000000000000",
		},
	}
	for _, tc := range tcases {
		mask, _ := NewBitMask(tc.firstBit, tc.secondBit)
		mask.Clear()
		if mask.String() != string(tc.clearedMask) {
			t.Errorf("Expected mask to be %v, got %v", tc.clearedMask, mask)
		}
	}
}

func TestFill(t *testing.T) {
	tcases := []struct {
		name       string
		filledMask string
	}{
		{
			name:       "Fill bit masks",
			filledMask: "1111111111111111111111111111111111111111111111111111111111111111",
		},
	}
	for _, tc := range tcases {
		mask, _ := NewBitMask()
		mask.Fill()
		if mask.String() != string(tc.filledMask) {
			t.Errorf("Expected mask to be %v, got %v", tc.filledMask, mask)
		}
	}
}

func TestIsEmpty(t *testing.T) {
	tcases := []struct {
		name          string
		maskBit       int
		expectedEmpty bool
	}{
		{
			name:          "Check if mask is empty",
			maskBit:       0,
			expectedEmpty: false,
		},
	}
	for _, tc := range tcases {
		mask, _ := NewBitMask(tc.maskBit)
		empty := mask.IsEmpty()
		if empty {
			t.Errorf("Expected value to be %v, got %v", tc.expectedEmpty, empty)
		}
	}
}

func TestIsSet(t *testing.T) {
	tcases := []struct {
		name        string
		maskBit     int
		expectedSet bool
	}{
		{
			name:        "Check if mask bit is set",
			maskBit:     0,
			expectedSet: true,
		},
	}
	for _, tc := range tcases {
		mask, _ := NewBitMask(tc.maskBit)
		set := mask.IsSet(tc.maskBit)
		if !set {
			t.Errorf("Expected value to be %v, got %v", tc.expectedSet, set)
		}
	}
}

func TestIsEqual(t *testing.T) {
	tcases := []struct {
		name          string
		firstMaskBit  int
		secondMaskBit int
		isEqual       bool
	}{
		{
			name:          "Check if two bit masks are equal",
			firstMaskBit:  0,
			secondMaskBit: 0,
			isEqual:       true,
		},
	}
	for _, tc := range tcases {
		firstMask, _ := NewBitMask(tc.firstMaskBit)
		secondMask, _ := NewBitMask(tc.secondMaskBit)
		isEqual := firstMask.IsEqual(secondMask)
		if !isEqual {
			t.Errorf("Expected mask to be %v, got %v", tc.isEqual, isEqual)
		}
	}
}

func TestCount(t *testing.T) {
	tcases := []struct {
		name          string
		maskBit       int
		expectedCount int
	}{
		{
			name:          "Count number of bits set in full mask",
			maskBit:       42,
			expectedCount: 1,
		},
	}
	for _, tc := range tcases {
		mask, _ := NewBitMask(tc.maskBit)
		count := mask.Count()
		if count != tc.expectedCount {
			t.Errorf("Expected value to be %v, got %v", tc.expectedCount, count)
		}
	}
}

func TestGetBits(t *testing.T) {
	tcases := []struct {
		name         string
		firstbit     int
		secondbit    int
		expectedbits []int
	}{
		{
			name:         "Get number of each bit which has been set",
			firstbit:     0,
			secondbit:    1,
			expectedbits: []int{0, 1},
		},
	}
	for _, tc := range tcases {
		mask, _ := NewBitMask(tc.firstbit, tc.secondbit)
		bits := mask.GetBits()
		if !reflect.DeepEqual(bits, tc.expectedbits) {
			t.Errorf("Expected value to be %v, got %v", tc.expectedbits, bits)
		}
	}
}

func TestIsNarrowerThan(t *testing.T) {
	tcases := []struct {
		name                  string
		firstMask             []int
		secondMask            []int
		expectedFirstNarrower bool
	}{
		{
			name:                  "Check narrowness of masks with unequal bits set 1/2",
			firstMask:             []int{0},
			secondMask:            []int{0, 1},
			expectedFirstNarrower: true,
		},
		{
			name:                  "Check narrowness of masks with unequal bits set 2/2",
			firstMask:             []int{0, 1},
			secondMask:            []int{0},
			expectedFirstNarrower: false,
		},
		{
			name:                  "Check narrowness of masks with equal bits set 1/2",
			firstMask:             []int{0},
			secondMask:            []int{1},
			expectedFirstNarrower: true,
		},
		{
			name:                  "Check narrowness of masks with equal bits set 2/2",
			firstMask:             []int{1},
			secondMask:            []int{0},
			expectedFirstNarrower: false,
		},
	}
	for _, tc := range tcases {
		firstMask, _ := NewBitMask(tc.firstMask...)
		secondMask, _ := NewBitMask(tc.secondMask...)
		expectedFirstNarrower := firstMask.IsNarrowerThan(secondMask)
		if expectedFirstNarrower != tc.expectedFirstNarrower {
			t.Errorf("Expected value to be %v, got %v", tc.expectedFirstNarrower, expectedFirstNarrower)
		}
	}
}

func TestIterateBitMasks(t *testing.T) {
	tcases := []struct {
		name    string
		numbits int
	}{
		{
			name:    "1 bit",
			numbits: 1,
		},
		{
			name:    "2 bits",
			numbits: 2,
		},
		{
			name:    "4 bits",
			numbits: 4,
		},
		{
			name:    "8 bits",
			numbits: 8,
		},
		{
			name:    "16 bits",
			numbits: 16,
		},
	}
	for _, tc := range tcases {
		// Generate a list of bits from tc.numbits.
		var bits []int
		for i := 0; i < tc.numbits; i++ {
			bits = append(bits, i)
		}

		// Calculate the expected number of masks. Since we always have masks
		// with bits from 0..n, this is just (2^n - 1) since we want 1 mask
		// represented by each integer between 1 and 2^n-1.
		expectedNumMasks := (1 << uint(tc.numbits)) - 1

		// Iterate all masks and count them.
		numMasks := 0
		IterateBitMasks(bits, func(BitMask) {
			numMasks++
		})

		// Compare the number of masks generated to the expected amount.
		if expectedNumMasks != numMasks {
			t.Errorf("Expected to iterate %v masks, got %v", expectedNumMasks, numMasks)
		}
	}
}
