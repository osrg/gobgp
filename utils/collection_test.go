// collection_test.go
package utils

import (
	"fmt"
	"testing"
)

func insertData(t *testing.T, oMap *OrderedMap, num int) (*OrderedMap, string) {
	var e error = nil
	for i := 0; i < num; i++ {
		arg := "test"
		key := i
		value := fmt.Sprintf("%s%d", arg, key)
		e = oMap.Append(key, value)
		if e != nil {
			t.Error(e)
		}
	}
	result := "FAIL"
	if e == nil {
		result = "OK"
	}
	return oMap, result
}

func getData(t *testing.T, oMap *OrderedMap, iNum int, deleteNum int) string {
	var result string
	for i := 0; i < iNum; i++ {
		if deleteNum == i {
			continue
		}
		arg := "test"
		key := i
		value := fmt.Sprintf("%s%d", arg, key)
		ans := oMap.Get(i)
		result = "OK"
		//fmt.Println(ans)
		if ans != value {
			result = "FAIL"
			break
		}
	}
	return result
}
func deleteData(t *testing.T, oMap *OrderedMap, iNum int, deleteNum int) string {
	e := oMap.Delete(deleteNum)
	result := "OK"
	if e != nil {
		result = "FAIL"
		t.Error(e)
		return result
	}
	result = getData(t, oMap, iNum, deleteNum)
	return result
}
func popData(t *testing.T, oMap *OrderedMap, iNum int, popNum int) string {
	arg := "test"
	value := fmt.Sprintf("%s%d", arg, popNum)
	getValue := oMap.Pop(popNum)
	result := "OK"
	fmt.Println(getValue)
	if value != getValue {
		result = "FAIL"
		t.Errorf("Different result < %s > < %s >", value, getValue)
		return result
	}
	result = getData(t, oMap, iNum, popNum)
	return result
}
func checkLen(t *testing.T, oMap *OrderedMap, iNum int) string {
	mLen := oMap.Len()
	result := "OK"
	if mLen != iNum {
		result = "FAIL"
		t.Errorf("Different result < %d > < %d >", mLen, iNum)
		return result
	}
	return result
}
func getkListData(t *testing.T, oMap *OrderedMap, iNum int) string {
	kList := oMap.KeyLists()
	mkLen := kList.Len()
	result := "OK"
	if mkLen != iNum {
		result = "FAIL"
		t.Errorf("Different result < %d > < %d >", mkLen, iNum)
		return result
	}
	i := 0
	for elem := kList.Front(); elem != nil; elem = elem.Next() {
		if elem.Value != i {
			result = "FAIL"
			break
		}
		i++
	}
	return result
}
func getvListData(t *testing.T, oMap *OrderedMap, iNum int) string {
	vList := oMap.ValueLists()
	mvLen := vList.Len()
	result := "OK"
	if mvLen != iNum {
		result = "FAIL"
		t.Errorf("Different result < %d > < %d >", mvLen, iNum)
		return result
	}
	arg := "test"
	i := 0
	for elem := vList.Front(); elem != nil; elem = elem.Next() {
		value := fmt.Sprintf("%s%d", arg, i)
		if elem.Value != value {
			result = "FAIL"
			break
		}
		i++
	}
	return result
}
func Test_Collection(t *testing.T) {
	// init
	var result string
	iNum := 10
	deleteNum := -1
	oMap := NewOrderedMap()
	// test
	t.Log("# INSERT")
	oMap, result = insertData(t, oMap, iNum)
	t.Log("# INSERT END -> [ ", result, " ]")
	t.Log("")
	t.Log("# GET ELEMENT")
	result = getData(t, oMap, iNum, deleteNum)
	t.Log("# INSERT ELEMENT END -> [ ", result, " ]")
	t.Log("")
	t.Log("# DELETE ELEMENT")
	deleteNum = 9
	result = deleteData(t, oMap, iNum, deleteNum)
	t.Log("# DELETE ELEMENT END -> [ ", result, " ]")
	t.Log("")
	t.Log("# POP ELEMENT")
	popNum := 9
	oMap = NewOrderedMap()
	oMap, result = insertData(t, oMap, iNum)
	result = popData(t, oMap, iNum, popNum)
	t.Log("# POP ELEMENT END -> [ ", result, " ]")
	t.Log("")
	t.Log("# CHECK LEN")
	oMap = NewOrderedMap()
	oMap, result = insertData(t, oMap, iNum)
	result = checkLen(t, oMap, iNum)
	t.Log("# CHECK LEN END -> [ ", result, " ]")
	t.Log("")
	t.Log("# GET KEY LIST")
	result = getkListData(t, oMap, iNum)
	t.Log("# GET KEY LIST END -> [ ", result, " ]")
	t.Log("")
	t.Log("# GET VALUE LIST")
	result = getvListData(t, oMap, iNum)
	t.Log("# GET VALUE LIST END -> [ ", result, " ]")
	t.Log("")
}
