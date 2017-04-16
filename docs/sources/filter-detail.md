# Detail of Policy configuration

This page shows how to write your own policies.

As [Policy configuration](https://github.com/osrg/gobgp/blob/master/docs/sources/policy.md) shows, you can put import or export policies to control the route advertisement. Basically a policy has condition part and an action part, and a condition part has prefix match and neighbor match. An action part has the rule to accept or reject(if it's import, otherwise discard) routes.

The policy configuration on GoBGP consists of DefinedSets and PolicyDefinitionList in its configuration file.

 - DefinedSets

 A single DefinedSets entry has prefix match thas is named PrefixSetList and neighbor match part that is named NeighborSetList and combines 2 parts with the name.
 It is possible to refer the combination using its name from policy.

 - PolicyDefinitionList

 PolicyDefinitionList is a list of policy.
 A single element of PolicyDefinitionList has statements that combine a condition with an action and we can say it's policy.


## Definition Steps

These are steps to define policy;

1. define DefinedSets
  - define PrefixSetList
  - define NeighborSetList
2. define PolicyDefinitionList
3. attach policies to a neighbor

### 1. Defining DefinedSets
DefineSets has prefix information and neighbor information in PrefixSetList and NeighborSetList section, and GoBGP uses these information to evaluate routes.
Defining DefinedSets is needed at first.
PrefixSetList and NeighborSetList section are prefix match part and neighbor match part.

- DefinedSets example

 ```
 [[DefinedSets.PrefixSetList]]
  PrefixSetName = "ps1"
  # prefix match part
  [[DefinedSets.PrefixSetList.PrefixList]]
   Address = "10.33.0.0"
   Masklength = 16
   MasklengthRange = 21...24
  # neighbor match part
  [[DefinedSets.NeighborSetList]]
   NeighborSetName = "ns1"
  [[DefinedSets.NeighborSetList.NeighborInfoList]]
   Address = "10.0.255.1"
 ```

---

#### PrefixSetList
PrefixSetList has PrefixList as its element. PrefixList has prefix information to match destination's address and we can specify route's NLRI inside.

PrefixList has 3 elements.

| Parent                                | Element         |Description        | Example    | Optional   |
| ------------------------------------- |-----------------|-------------------|------------|------------|
| DefinedSets.PrefixSetList             | PrefixSetName   | name of PrefixSet | "10.33.0.0"|            |
| DefinedSets.PrefixSetList.PrefixList  | Address         | prefix address    | "10.33.0.0"|            |
|                                       | Masklength      | prefix length     | 16         |            |
|                                       | MasklengthRange | range of length   | "25..28"   | Yes        |


##### Examples
- example 1
  - Match routes whose high order 2 octets of NLRI is 10.33 and its prefix length is between from 21 to 24

 ```
 # example 1
 [[DefinedSets.PrefixSetList]]
  PrefixSetName = "ps1"
 [[DefinedSets.PrefixSetList.PrefixList]]
  Address = "10.33.0.0"
  Masklength = 16
  MasklengthRange = "21...24"
 ```

  - If you define a PrefixList that doesn't have MasklengthRange, it matches routes that have just 10.33.0.0/16 as NLRI.


- example 2
  - If you want to evaluate multiple routes with a single PrefixSetList, you can do this by adding an another PrefixList like this;

 ```
 # example 2
 [[DefinedSets.PrefixSetList]]
  PrefixSetName = "ps1"
 [[DefinedSets.PrefixSetList.PrefixList]]
  Address = "10.33.0.0"
  Masklength = 16
  MasklengthRange = "21...24"
 [[DefinedSets.PrefixSetList.PrefixList]]
  Address = "10.50.0.0"
  Masklength = 16
  MasklengthRange = "21...24"
 ```
  - This prefix match checks if a route has 10.33.0.0/21 to 24 **or** 10.50.0.0/21 to 24.


- example 3
  - PrefixSetName under PrefixSetList is reference to a single PrefixSet.
  - If you want to add different PrefixSet more, you can add other blocks that form the same structure with example 1.

 ```
 # example 3
 # PrefixSetList
 [[DefinedSets.PrefixSetList]]
 PrefixSetName = "ps1"
 [[DefinedSets.PrefixSetList.PrefixList]]
 Address = "10.33.0.0"
 Masklength = 16
 MasklengthRange = "21...24"
 # another PrefixSetList
 [[DefinedSets.PrefixSetList]]
 PrefixSetName = "ps2"
 [[DefinedSets.PrefixSetList.PrefixList]]
 Address = "10.50.0.0"
 Masklength = 16
 MasklengthRange = "21...24"
 ```

---

#### NeighborSetList

NeighborSetList has NeighborInfoList as its element and NeighborInfoList has neighbor information to match the sender of the routes.
It is necessary to specify a neighbor address in NeighborInfoList.
NeighborInfoList has 1 elements.

| Parent                                        | Element  |Description         | Example     | Optional   |
| --------------------------------------------- |----------|--------------------|-------------|------------|
| DefinedSets.NeighborSetList                   | Name     | name of NeighborSet| "ns1       "|            |
| DefinedSets.NeighborSetList.NeighborInfoList  | Address  | neighbor's address | "10.0.255.1"|            |

##### Examples

- example 1
  - Match routes which come from the neighbor 10.0.255.1

 ```
 # example 1
 [[DefinedSets.NeighborSetList]]
  NeighborSetName = "ns1"
  [[DefinedSets.NeighborSetList.NeighborInfoList]]
   Address = "10.0.255.1"
 ```

- example 2
  - Match routes which come from the neighbor 10.0.255.1
Neighbor Match needs be defined within DefinedSets as follows.
 ```
 # example 2
 [[DefinedSets.NeighborSetList]]
 NeighborSetName = "ns2"
  [[DefinedSets.NeighborSetList.NeighborInfoList]]
   Address = "10.0.255.1"
 ```

- example 3
  - As with PrefixSet, NeighborSet can have multiple NeighborInfoList like this;

 ```
 # example 3
 [[DefinedSets.NeighborSetList]]
 NeighborSetName = "ns3"
  [[DefinedSets.NeighborSetList.NeighborInfoList]]
   Address = "10.0.255.1"
  [[DefinedSets.NeighborSetList.NeighborInfoList]]
   Address = "10.0.255.2"
 ```

 - - This example checks if a route comes from neighbor 10.0.255.1 **or** 10.0.255.2.

---

### 2. Defining PolicyDefinitionList
PolicyDefinitionList consists of condition and action of the policy. The condition part evaluates routes from neighbors and applies action if the routes match a condition. For the definition of PolicyDefinitionList, you can use DefinedSets above to specify conditions.

PolicyDefinitionList has PolicyDefinition as its element and the PolicyDefinition is just a policy.
You can write condition and action under StatementList.

 - an example of PolicyDefinitionList

 ```
 [[PolicyDefinitionList]]
  Name = "example-policy"
 [[PolicyDefinitionList.StatementList]]
  Name = "statement1"
 [PolicyDefinitionList.StatementList.Conditions]
  MatchPrefixSet = "ps2"
  MatchNeighborSet = "ns1"
  MatchSetOptions = 1
 [PolicyDefinitionList.StatementList.Actions]
  RejectRoute = true
 ```

The elements of PolicyDefinitionList are as follows;

| Parent                                         | Element          |Description                                                                                   |Example|
| ---------------------------------------------- |------------------|-----------------------------------------------------------------------------------------------|------|
| PolicyDefinitionList                           | name             | policy's name                                                                                 | "pd1"|
| PolicyDefinitionList.StatementList             | name             | statements's name                                                                             | "pd1"|
| PolicyDefinitionList.StatementList.Conditions  | MatchPrefixSet   | prefix match name used in its policy definition                                               | "ps2"|
|                                                | MatchNeighborSet | neighbor match name used in its policy definition                                             |"ns1" |
|                                                | MatchSetOptions  | option for the check;<br> 0 means **ANY**,<br>  1 means **ALL**,<br>  2 means **INVERT**                    | 1    |
|PolicyDefinitionList.StatementList.Actions      | RejectRoute      | action for the route which matches PrefixSet and NeighborSet. if true, this route is rejected | true |

##### Examples
 - example 1
  - This PolicyDefinition has PrefixSet *ps1* and NeighborSet *ns1* as its condition and routes matche the condition is rejected.

 ```
 # example 1
 [[PolicyDefinitionList]]
 Name = "policy1"
 [[PolicyDefinitionList.StatementList]]
 Name = "statement1"
 [PolicyDefinitionList.StatementList.Conditions]
 MatchPrefixSet = "ps2"
 MatchNeighborSet = "ns1"
 MatchSetOptions = 1
 [PolicyDefinitionList.StatementList.Actions]
 RejectRoute = true
 ```

- example 2
 - PolicyDefinition has two statements

 ```
 # example 2
 [[PolicyDefinitionList]]
 Name = "pd1"
 # first statement - (1)
 [[PolicyDefinitionList.StatementList]]
  Name = "statement1"
 [PolicyDefinitionList.StatementList.Conditions]
  MatchPrefixSet = "ps1"
  MatchNeighborSet = "ns1"
  MatchSetOptions = 1
 [PolicyDefinitionList.StatementList.Actions]
  RejectRoute = true
 # second statement - (2)
 [[PolicyDefinitionList.StatementList]]
  Name = "statement2"
 [PolicyDefinitionList.StatementList.Conditions]
  MatchPrefixSet = "ps2"
  MatchNeighborSet = "ns2"
  MatchSetOptions = 1
 [PolicyDefinitionList.StatementList.Actions]
  RejectRoute = true
 ```
  - if a route matches the condition inside the first statement(1), GoBGP applies its action and quits the policy evaluation.


- example 3
 - If you want to add other policies, just add PolicyDefinitionList block following the first one like this;
 ```
 # example 3
 # first policy
 [[PolicyDefinitionList]]
 Name = "policy1"

 [[PolicyDefinitionList.StatementList]]
 Name = "statement1"
 [PolicyDefinitionList.StatementList.Conditions]
 MatchPrefixSet = "ps1"
 MatchNeighborSet = "ns1"
 MatchSetOptions = 1
 [PolicyDefinitionList.StatementList.Actions]
 RejectRoute = true

# second policy
 [[PolicyDefinitionList]]
 Name = "policy2"

 [[PolicyDefinitionList.StatementList]]
 Name = "statement2"
 [PolicyDefinitionList.StatementList.Conditions]
 MatchPrefixSet = "ps2"
 MatchNeighborSet = "ns2"
 MatchSetOptions = 1
 [PolicyDefinitionList.StatementList.Actions]
 RejectRoute = true
 ```

---

### 3. Attaching policy
You can attach policies to a neighbor after defining policy.
To attach policies to a neighbor, you need to add policy's name to NeighborList.ApplyPolicy in the neighbor's setting.

You can attach policies to the import policy or the export policy inside the neighbor configuration.
This example attatches *policy1* to import policy and *policy2* to export policy.

```
[[NeighborList]]
NeighborAddress = "10.0.255.2"
PeerAs = 65002
[NeighborList.RouteServer]
RouteServerClient = true
[NeighborList.ApplyPolicy]
ImportPolicies = ["policy1"]
ExportPolicies = ["policy2"]
DefaultImportPolicy = 0
DefaultExportPolicy = 0
```

NeighborList has a section to specify policies and the section's name is ApplyPolicy.
The ApplyPolicy has 4 elements.

| Parent                    | Element             | Description                                                                   | Example    |
|---------------------------|---------------------|-------------------------------------------------------------------------------|------------|
| NeighborList.ApplyPolicy  | ImportPolicies      | PolicyDefinitionList.name for import policy                                   | "policy1"  |
|                           | ExportPolicies      | PolicyDefinitionList.name for export policy                                   | "policy1"  |
|                           | DefaultImportPolicy | action if the route isn't applied any policy;<br> 0 means import,<br>  1 means reject  | 0 |
|                           | DefaultExportPolicy | action if the route isn't applied any policy;<br> 0 means export,<br>  1 means discard | 0 |
