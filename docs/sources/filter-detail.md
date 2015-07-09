

# Detail of Policy Configuration

This page shows how to write your own policies.

As [Policy configuration](https://github.com/osrg/gobgp/blob/master/docs/sources/policy.md) shows, 
you can define import or export policies or distribute policies to control the route advertisement. 

Note: The distribute policy is applied only when the peer is Route Server client.

Basically a policy has condition part and an action part. The condition part can be defined with attributes below:
 - prefix
 - neighbor
 - aspath
 - aspath length
 - community

A action part is below:
 - accept or reject
 - add/replace/remove community or remove all communities
 - add/subtract or replace MED value
 - prepend AS number in the AS_PATH attribute


GoBGP's configuration file has two parts named DefinedSets and PolicyDefinitionList as its policy configuration.

 - DefinedSets

 A single DefinedSets entry has prefix match that is named PrefixSetList and neighbor match part that is named NeighborSetList. It also has BgpDefinedSets, a subset of DefinedSets that defines conditions referring to BGP attributes such as aspath. This DefinedSets has a name and it's used to refer to DefinedSets items from outside.

 - PolicyDefinitionList

 PolicyDefinitionList is a list of policy.
 A single element of PolicyDefinitionList has a statement part that combines conditions with an action.


## Definition Steps

These are steps to define policy:

1. define DefinedSets
  1. define PrefixSetList
  1. define NeighborSetList
1.  define BgpDefinedSets
  1. define CommunitySetList
  1. define AsPathSetList
1. define PolicyDefinitionList
1. attach policies to a neighbor

----

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

  ----

 #### PrefixSetList
 PrefixSetList has PrefixList as its element. PrefixList has prefix information to match destination's address and we can specify route's NLRI inside.

 PrefixList has 3 elements.

 | Element         |Description        | Example    | Optional   |
 |-----------------|-------------------|------------|------------|
 | PrefixSetName   | name of PrefixSet | "10.33.0.0"|            |
 | Address         | prefix address    | "10.33.0.0"|            |
 | Masklength      | prefix length     | 16         |            |
 | MasklengthRange | range of length   | "25..28"   | Yes        |


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
   - If you want to evaluate multiple routes with a single PrefixSetList, you can do this by adding an another PrefixList like this:

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

  ----

 #### NeighborSetList

 NeighborSetList has NeighborInfoList as its element and NeighborInfoList has neighbor information to match the sender of the routes.
 It is necessary to specify a neighbor address in NeighborInfoList.

 NeighborInfoList has 2 elements.

 | Element         |Description          | Example      | Optional   |
 |-----------------|---------------------|--------------|------------|
 | NeighborSetName | name of NeighborSet | "ns1"        |            |
 | Address         | neighbor's address  | "10.0.255.1" |            |

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

  ```
  # example 2
  [[DefinedSets.NeighborSetList]]
  NeighborSetName = "ns2"
   [[DefinedSets.NeighborSetList.NeighborInfoList]]
    Address = "10.0.255.1"
  ```

 - example 3
    - As with PrefixSet, NeighborSet can have multiple NeighborInfoList like this.
    - This example checks if a route comes from neighbor 10.0.255.1 **or** 10.0.255.2.

  ```
  # example 3
  [[DefinedSets.NeighborSetList]]
  NeighborSetName = "ns3"
   [[DefinedSets.NeighborSetList.NeighborInfoList]]
    Address = "10.0.255.1"
   [[DefinedSets.NeighborSetList.NeighborInfoList]]
    Address = "10.0.255.2"
  ```

---

### 2. Defining BgpDefinedSets

BgpDefinedSets has Community information, Extended Community information and AS_PATH information in each SetList section respectively. And it is a child element of DefinedSets.
CommunitySetList, ExtCommunitySetList and AsPathSetList section are each match part.

- BgpDefinedSets example

 ```
   [DefinedSets.BgpDefinedSets]
     # Community match part
     [[DefinedSets.BgpDefinedSets.CommunitySetList]]
       CommunitySetName = "community1"
       CommunityMembers = ["65100:10"]
     # Extended Community match part
     [[DefinedSets.BgpDefinedSets.ExtCommunitySetList]]
       ExtCommunitySetName = "ecommunity1"
       ExtCommunityMembers = ["RT:65001:200"]
     # AS_PATH match part
     [[DefinedSets.BgpDefinedSets.AsPathSetList]]
       AsPathSetName = "aspath1"
       AsPathSetMembers = ["^65100"]
 ```

  ----

 #### CommunitySetList
 CommunitySetList has Community value as its element. The values are used to evaluate communities held by the destination.

 CommunitySetList has 2 elements.

 | Element          | Description             | Example      | Optional |
 |------------------|-------------------------|--------------|----------|
 | CommunitySetName | name of CommunitySet    | "community1" |          |
 | CommunityMembers | list of Community value | ["65100:10"] |          |

 You can use regular expressions to specify communities in CommunityMembers element.

 ##### Examples
 - example 1
   - Match routes which has "65100:10" as a community value.

  ```
  # example 1
 [DefinedSets.BgpDefinedSets]
   [[DefinedSets.BgpDefinedSets.CommunitySetList]]
     CommunitySetName = "community1"
     CommunityMembers = ["65100:10"]
  ```

 - example 2
    - Specifying community by regular expression
    - You can use regular expressions that is available in Golang.

  ```
  # example 2
  [DefinedSets.BgpDefinedSets]
   [[DefinedSets.BgpDefinedSets.CommunitySetList]]
   CommunitySetName = "community2"
   CommunityMembers = ["6[0-9]+:[0-9]+"]
  ```
   ----

 #### ExtCommunitySetList
 ExtCommunitySetList has Extended Community value as its element. The values are used to evaluate extended communities held by the destination.

 ExtCommunitySetList has 2 elements.

 | Element             | Description                | Example          | Optional |
 |---------------------|----------------------------|------------------|----------|
 | ExtCommunitySetName | name of ExtCommunitySet    | "ecommunity1"    |          |
 | ExtCommunityMembers | list of ExtCommunity value | ["RT:65001:200"] |          |

 You can use regular expressions to specify extended communities in ExtCommunityMembers element.
 However: the first one element separated by (part of "RT") does not support to the regular expression.
 part of "RT" indicate sub type of extended community and using sub type as follows:

  - RT: mean the route target.
  - SoO: mean the site of origin(route origin).


 ##### Examples
 - example 1
      - Match routes which has "RT:65001:200" as a extended community value.

  ```
  # example 1
 [DefinedSets.BgpDefinedSets]
   [[DefinedSets.BgpDefinedSets.ExtCommunitySetList]]
     ExtCommunitySetName = "ecommunity1"
     ExtCommunityMembers = ["RT:65001:200"]
  ```

 - example 2
    - Specifying extended community by regular expression
    - You can use regular expressions that is available in Golang.

  ```
  # example 2
 [DefinedSets.BgpDefinedSets]
   [[DefinedSets.BgpDefinedSets.ExtCommunitySetList]]
     ExtCommunitySetName = "ecommunity1"
     ExtCommunityMembers = ["RT:6[0-9]+:[0-9]+"]
  ```

   ----


 #### AsPathSetList
 AsPathSetList has AS numbers as its element. The numbers are used to evaluate AS numbers in the destination's AS_PATH attribute.

   CommunitySetList has 2 elements.

 | Element          | Description       | Example    | Optional |
 |------------------|-------------------|------------|----------|
 | AsPathSetName    | name of AsPathSet | "aspath1"  |          |
 | AsPathSetMembers | list of AS number | ["^65100"] |          |

   You can specify the position using regexp-like expression as follows:
   - From: "^65100" means the route is passed from AS 65100 directly.
   - Any: "65100" means the route comes through AS 65100.
   - Origin: "65100$" means the route is originated by AS 65100.
   - Only: "^65100$" means the route is originated by AS 65100 and comes from it directly.

   ##### Examples
   - example 1
     - Match routes which come from AS 65100.

    ```
    # example 1
   [DefinedSets.BgpDefinedSets]
     [[DefinedSets.BgpDefinedSets.AsPathSetList]]
     AsPathSetName = "aspath1"
     AsPathSetMembers = ["^65100"]
    ```

---

### 3. Defining PolicyDefinitionList
PolicyDefinitionList consists of condition and action of the policy. The condition part evaluates routes from neighbors and applies action if the routes match conditions. You can use DefinedSets above and other conditions to specify conditions in the PolicyDefinitionList.

PolicyDefinitionList has PolicyDefinition as its element and the PolicyDefinition is a policy itself.
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
  [PolicyDefinitionList.StatementList.Conditions.BgpConditions]
  MatchCommunitySet = "community1"
  MatchAsPathSet = "aspath1"
  [PolicyDefinitionList.StatementList.Conditions.BgpConditions.AsPathLength]
    Operator = "eq"
    Value = 2
 [PolicyDefinitionList.StatementList.Actions]
  AcceptRoute = true
  [PolicyDefinitionList.StatementList.Actions.BgpActions]
    SetMed = "-200"
    [PolicyDefinitionList.StatementList.Actions.BgpActions.SetCommunity]
      Communities = ["65100:20"]
      Options = "ADD"
    [PolicyDefinitionList.StatementList.Actions.BgpActions.SetAsPathPrepend]
      As = "65005"
      RepeatN = 5
 ```

 The elements of PolicyDefinitionList are as follows:

  - PolicyDefinitionList

 | Element | Description   | Example          |
 |---------|---------------|------------------|
 | name    | policy's name | "example-policy" |

  - PolicyDefinitionList.StatementList

 | Element | Description   | Example            |
 |---------|---------------|--------------------|
 | name    | statements's name | "statement1"   |

  - PolicyDefinitionList.StatementList.Conditions

 | Element          | Description                                                                              | Example |
 |------------------|------------------------------------------------------------------------------------------|---------|
 | MatchPrefixSet   | name for DefinedSets.PrefixSetList that is used in this policy                           | "ps2"   |
 | MatchNeighborSet | name for DefinedSets.NeighborSetList that is used in this policy                         | "ns1"   |
 | MatchSetOptions  | option for the check:<br> 0 means **ANY**,<br>  1 means **ALL**,<br>  2 means **INVERT** | 1       |


  - PolicyDefinitionList.StatementList.Conditions.BgpConditions

 | Element           | Description                                                                      | Example      |
 |-------------------|----------------------------------------------------------------------------------|--------------|
 | MatchCommunitySet | name for DefinedSets.BgpDefinedSets.CommunitySetList that is used in this policy | "community1" |
 | MatchAsPathSet    | name for DefinedSets.BgpDefinedSets.AsPathSetList that is used in this policy    | "aspath1"    |


  - PolicyDefinitionList.StatementList.Conditions.BgpConditions.AsPathLength

 | Element  | Description                                                                                        | Example |
 |----------|----------------------------------------------------------------------------------------------------|---------|
 | Operator | operator to compare the length of AS number in AS_PATH attribute. <br> "eq","ge","le" can be used. <br> "eq" means that length of AS number is equal to Value element <br> "ge" means that length of AS number is equal or greater than the Value element <br> "le" means that length of AS number is equal or smaller than the Value element| "eq"    |
 | Value    | value used to compare with the length of AS number in AS_PATH attribute                            | 2       |


  - PolicyDefinitionList.StatementList.Actions

 | Element     | Description                                                                       | Example |
 |-------------|-----------------------------------------------------------------------------------|---------|
 | AcceptRoute | action to accept the route if matches conditions. If true, this route is accepted | true    |

  - PolicyDefinitionList.StatementList.Actions.BgpActions

 | Element | Description                                                                      | Example |
 |---------|----------------------------------------------------------------------------------|---------|
 | SetMed  | SetMed used to change the med value of the route. <br> If only numbers have been specified, replace the med value of route.<br> if number and operater(+ or -) have been specified, adding or subtracting the med value of route. | "-200"    |

  - PolicyDefinitionList.StatementList.Actions.BgpActions.SetCommunity

 | Element     | Description                                                                      | Example |
 |-------------|----------------------------------------------------------------------------------|---------|
 | Communities | communities used to manipulate the route's community accodriong to Options below | "65100:20"    |
 | Options     | operator to manipulate Community attribute in the route                          | "ADD"       |

  - PolicyDefinitionList.StatementList.Actions.BgpActions.SetAsPathPrepend
  
 | Element | Description                                                                                           | Example |
 |---------|-------------------------------------------------------------------------------------------------------|---------|
 | As      | AS number to prepend. You can use "last-as" to prepend the leftmost AS number in the aspath attribute.| "65100" |
 | RepeatN | repeat count to prepend AS                                                                            |    5    |

 <br>

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
 Name = "policy1"
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
  - If you want to add other policies, just add PolicyDefinitionList block following the first one like this

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

 - example 4
  - This PolicyDefinition has multiple conditions including BgpConditions as follows:
    - PrefixSet: *ps1*
    - NeighborSet: *ns1*
    - CommunitySet: *community1*
    - AsPathSet: *aspath1*
    - AsPath length: *equal 2*

  - If a route matches all these conditions, the route is accepted and added community "65100:20" and subtracted 200 from med value and prepended 65005 five times in its AS_PATH attribute.

 ```
 # example 4
 [[PolicyDefinitionList]]
 Name = "policy1"
 [[PolicyDefinitionList.StatementList]]
 Name = "statement1"
 [PolicyDefinitionList.StatementList.Conditions]
 MatchPrefixSet = "ps1"
 MatchNeighborSet = "ns1"
 MatchSetOptions = 1
 [PolicyDefinitionList.StatementList.Conditions.BgpConditions]
 MatchCommunitySet = "community1"
 MatchAsPathSet = "aspath1"
 [PolicyDefinitionList.StatementList.Conditions.BgpConditions.AsPathLength]
 Operator = "eq"
 Value = 2
 [PolicyDefinitionList.StatementList.Actions]
 AcceptRoute = true
 [PolicyDefinitionList.StatementList.Actions.BgpActions]
 SetMed = "-200"
 [PolicyDefinitionList.StatementList.Actions.BgpActions.SetCommunity]
 Communities = ["65100:20"]
 Options = "ADD"
 [PolicyDefinitionList.StatementList.Actions.BgpActions.SetAsPathPrepend]
 As = "65005"
 RepeatN = 5
 ```


---

### 4. Attaching policy
You can use policies defined above as import or export or distribtue policy by
attaching them to neighbors.

   Note: The distribute policy is applied only when the peer is Route Server client.

To attach policies to neighbors, you need to add policy's name to NeighborList.ApplyPolicy in the neighbor's setting.
This example attatches *policy1* to import policy and *policy2* to export policy and *policy3* is used as the distribute policy.

```
[[NeighborList]]
NeighborAddress = "10.0.255.2"
PeerAs = 65002
[NeighborList.RouteServer]
RouteServerClient = true
[NeighborList.ApplyPolicy]
ImportPolicies = ["policy1"]
ExportPolicies = ["policy2"]
DistributePolicies = ["policy3"]
DefaultImportPolicy = 0
DefaultExportPolicy = 0
DefaultDistributePolicy = 0
```

NeighborList has a section to specify policies and the section's name is ApplyPolicy.
The ApplyPolicy has 6 elements.

| Element                 | Description                                                                                 | Example    |
|-------------------------|---------------------------------------------------------------------------------------------|------------|
| ImportPolicies          | PolicyDefinitionList.name for import policy                                                 | "policy1"  |
| ExportPolicies          | PolicyDefinitionList.name for export policy                                                 | "policy2"  |
| DistributePolicies      | PolicyDefinitionList.name for distribute policy                                             | "policy3"  |
| DefaultImportPolicy     | action when the route doesn't match any policy:<br> 0 means import,<br>  1 means reject     | 0          |
| DefaultExportPolicy     | action when the route doesn't match any policy:<br> 0 means export,<br>  1 means discard    | 0          |
| DefaultDistributePolicy | action when the route doesn't match any policy:<br> 0 means distribute,<br>  1 means reject | 0          |
