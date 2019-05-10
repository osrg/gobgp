// Copyright (C) 2018 Nippon Telegraph and Telephone Corporation.
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

package version

import "fmt"

const MAJOR uint = 2
const MINOR uint = 4
const PATCH uint = 0

var SHA string = ""
var TAG string = ""

func Version() string {
	var suffix string = ""
	if len(TAG) > 0 {
		suffix = fmt.Sprintf("-%s", TAG)
	}

	if len(SHA) > 0 {
		suffix = fmt.Sprintf("%s+sha.%s", suffix, SHA)
	}

	return fmt.Sprintf("%d.%d.%d%s", MAJOR, MINOR, PATCH, suffix)
}