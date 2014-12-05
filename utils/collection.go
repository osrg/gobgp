// Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"container/list"
	"fmt"
	"reflect"
)

// Elements of abstraction the key.
type K struct {
	Element interface{}
}

/*
// Elements of abstraction the key.
type V struct {
	Element interface{}
}
*/
/*	This method may be required
func (e *E) Elem() interface{} {
	return e.Element
}
*/

// Structure for extending the map collection.
//
// keyType : Key type of Map .
// keyType : Value type of Map.
// TMap      : Map of the object to be extended.
// TOrder    : Insertion order list of map.
type OrderedMap struct {
	keyType interface{}
	valType interface{}
	TMap    map[K]interface{}
	TOrder  *list.List
}

// Constructor of OrderedMap.
func NewOrderedMap() *OrderedMap {
	om := &OrderedMap{}
	om.TMap = make(map[K]interface{})
	om.TOrder = list.New()
	return om
}

// Check whether the same of type of Map and List
//
// Returns: - error contents
//                 and nil if no error occurred.
func (om *OrderedMap) checkType(keyInfs interface{}, valInfs interface{}) (e error) {
	if om.keyType == nil && om.valType == nil {
		om.keyType = keyInfs
		om.valType = valInfs
		return nil
	} else {
		if reflect.TypeOf(om.keyType) != reflect.TypeOf(keyInfs) {
			return fmt.Errorf("Map Key Type mismatch [ %s ] and [ %s ].", reflect.TypeOf(om.keyType), reflect.TypeOf(keyInfs))
		}
	}
	return nil
}

// Check whether the same key exists in the map
//
// Returns: - error contents
//                 and nil if no error occurred.
func (om *OrderedMap) checkDuplicate(keyInfs interface{}) (e error) {
	for elem := om.TOrder.Front(); elem != nil; elem = elem.Next() {
		if elem.Value == keyInfs {
			return fmt.Errorf("Map key Duplicated [%s].", elem.Value)
		}
	}
	return
}

// Append Elements to Map
//
// Returns: - error contents
//                 and nil if no error occurred.
func (om *OrderedMap) Append(keyInfs interface{}, valInfs interface{}) (e error) {
	e = om.checkType(keyInfs, valInfs)
	if e != nil {
		return e
	}
	// Append key Elements to Map
	om.TMap[K{Element: keyInfs}] = valInfs
	e = om.checkDuplicate(K{Element: keyInfs})
	if e != nil {
		/*
			for elem := om.TOrder.Front(); elem != nil; elem = elem.Next() {
				if elem.Value == (K{Element: keyInfs}) {
					tmp := elem.Next()
					om.TOrder.Remove(elem)
					elem = tmp
				}
			}*/
		return nil
	}
	// Append Elements to List
	om.TOrder.PushBack(K{Element: keyInfs})
	return nil
}

// Get Elements from receive parameter.
//
// Returns: - Value of Map
//                 Return the interface that value has entered the Map.
func (om *OrderedMap) Get(keyInfs interface{}) interface{} {
	elem := om.TMap[K{Element: keyInfs}]
	return elem
}

// Convert Map keys to List.
//
// Returns: - List of Map Keys
func (om *OrderedMap) KeyLists() *list.List {
	keys := list.New()
	for key := om.TOrder.Front(); key != nil; key = key.Next() {
		keyElem := key.Value.(K).Element
		keys.PushBack(keyElem)
	}
	return keys
}

// Convert Map values to List.
//
// Returns: - List of Map Values
func (om *OrderedMap) ValueLists() *list.List {
	vals := list.New()
	for key := om.TOrder.Front(); key != nil; key = key.Next() {
		keyElem := key.Value.(K).Element
		value := om.Get(keyElem)
		vals.PushBack(value)
	}
	return vals
}

// Get Map length
//
// Returns: - Length of the map Element.
func (om *OrderedMap) Len() int {
	return om.TOrder.Len()
}

// Delete Map Element
//
// Returns: - error contents
//                 and nil if no error occurred.
func (om *OrderedMap) Delete(keyInfs interface{}) (e error) {
	// Delete key Elements from Map
	delete(om.TMap, K{Element: keyInfs})
	// Delete key Elements from List
	for elem := om.TOrder.Front(); elem != nil; elem = elem.Next() {
		if elem.Value == (K{Element: keyInfs}) {
			tmp := elem.Next()
			if tmp == nil {
				break
			}
			om.TOrder.Remove(elem)
			elem = tmp
		}
	}
	return
}

// Get Elements from Map and delete from List
//
// Returns: - Value of Map
//                 Return the interface that value has entered the Map.
func (om *OrderedMap) Pop(keyInfs interface{}) interface{} {
	elem := om.TMap[K{Element: keyInfs}]
	key := (K{Element: keyInfs}).Element
	om.Delete(key)
	return elem
}

// Clear Map and List
func (om *OrderedMap) Clear() {
	om.keyType = nil
	om.valType = nil
	om.TMap = make(map[K]interface{})
	om.TOrder = list.New()
}
