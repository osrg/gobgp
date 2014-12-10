// collection_test.go
package utils

import (
	"container/list"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestOrderedMapNew(t *testing.T) {
	oMap1 := NewOrderedMap()
	oMap2 := new(OrderedMap)
	oMap2.TMap = make(map[K]interface{})
	oMap2.TOrder = list.New()
	assert.NotNil(t, oMap1)
	assert.Equal(t, oMap1, oMap2)
}

func TestOrderedMapAppend(t *testing.T) {
	oMap := NewOrderedMap()
	e := oMap.Append(1, "test1")
	assert.NoError(t, e)
	expected := "test1"
	assert.Equal(t, expected, oMap.Get(1).(string))
}

func TestOrderedMapGet(t *testing.T) {
	oMap := NewOrderedMap()
	e := oMap.Append(2, "test2")
	assert.NoError(t, e)
	expected := "test2"
	assert.Nil(t, oMap.Get(1))
	assert.Equal(t, expected, oMap.Get(2).(string))
	assert.Nil(t, oMap.Get(3))
}

func TestOrderedMapDelete(t *testing.T) {
	oMap := NewOrderedMap()
	e := oMap.Append(3, "test3")
	assert.NoError(t, e)
	expected := "test3"
	assert.Equal(t, expected, oMap.Get(3).(string))
	oMap.Delete(3)
	assert.Nil(t, oMap.Get(3))
}

func TestOrderdMapPop(t *testing.T) {
	oMap := NewOrderedMap()
	e := oMap.Append(4, "test4")
	assert.NoError(t, e)
	expected := "test4"
	assert.Equal(t, expected, oMap.Pop(4).(string))
	assert.Nil(t, oMap.Get(4))
}

func TestOrderdMapLen(t *testing.T) {
	oMap := NewOrderedMap()
	count := 10
	for i := 0; i < count; i++ {
		e := oMap.Append(i, "test")
		assert.NoError(t, e)
	}
	assert.Equal(t, count, oMap.Len())
}

func TestOrderdMapKeyLists(t *testing.T) {
	oMap := NewOrderedMap()
	count := 10
	for i := 0; i < count; i++ {
		str := fmt.Sprintf("%s%d", "test", i)
		e := oMap.Append(i, str)
		assert.NoError(t, e)
	}
	expectedList := list.New()
	for i := 0; i < count; i++ {
		expectedList.PushBack(i)
	}
	kList := oMap.KeyLists()
	assert.Equal(t, expectedList, kList)
}

func TestOrderdMapValueLists(t *testing.T) {
	oMap := NewOrderedMap()
	count := 10
	for i := 0; i < count; i++ {
		str := fmt.Sprintf("%s%d", "test", i)
		e := oMap.Append(i, str)
		assert.NoError(t, e)
	}
	expectedList := list.New()
	for i := 0; i < count; i++ {
		str := fmt.Sprintf("%s%d", "test", i)
		expectedList.PushBack(str)
	}
	vList := oMap.ValueLists()
	assert.Equal(t, expectedList, vList)
}

func TestOrderedMapDiffKeyType(t *testing.T) {
	oMap := NewOrderedMap()
	e1 := oMap.Append(11, "test11")
	assert.NoError(t, e1)
	e2 := oMap.Append("test12", "test12")
	assert.Error(t, e2)
	//t.Log(e2)
}

func TestOrderedMapDiffValueType(t *testing.T) {
	oMap := NewOrderedMap()
	e1 := oMap.Append(13, "test13")
	assert.NoError(t, e1)
	e2 := oMap.Append(14, 14)
	assert.NoError(t, e2)
	expectedStr := "test13"
	expectedNum := 14
	assert.Equal(t, expectedStr, oMap.Get(13).(string))
	assert.Equal(t, expectedNum, oMap.Get(14).(int))
}

func TestOrderedMapDupKey(t *testing.T) {
	oMap := NewOrderedMap()
	e1 := oMap.Append(15, "test15")
	assert.NoError(t, e1)
	e2 := oMap.Append(15, "test15-1")
	assert.NoError(t, e2)
	expected := "test15-1"
	assert.Equal(t, oMap.Get(15).(string), expected)
}

func TestOrderedMapElementsOfStruct(t *testing.T) {
	oMap := NewOrderedMap()
	ks1 := &KeyStructT{1, "test1"}
	ks2 := &KeyStructT{2, "test2"}
	vs1 := &ValStructT{"test1", 1}
	vs2 := &ValStructT{"test2", 2}
	vs1expected := &ValStructT{"test1", 1}
	vs2expected := &ValStructT{"test2", 2}
	e1 := oMap.Append(ks1, vs1)
	assert.NoError(t, e1)
	e2 := oMap.Append(ks2, vs2)
	assert.NoError(t, e2)
	assert.Equal(t, vs1expected, oMap.Get(ks1))
	assert.Equal(t, vs2expected, oMap.Get(ks2))
}

type KeyStructT struct {
	a int
	b string
}

type ValStructT struct {
	c string
	d int
}
