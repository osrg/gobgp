

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
 - extended community

A action part is below:
 - accept or reject
 - add/replace/remove community or remove all communities
 - add/subtract or replace MED value
 - prepend AS number in the AS_PATH attribute


GoBGP's configuration file has two parts named DefinedSets and PolicyDefinitions as its policy configuration.

 - DefinedSets

 A single DefinedSets entry has prefix match that is named PrefixSets and neighbor match part that is named NeighborSets. It also has BgpDefinedSets, a subset of DefinedSets that defines conditions referring to BGP attributes such as aspath. This DefinedSets has a name and it's used to refer to DefinedSets items from outside.

 - PolicyDefinitions

 PolicyDefinitions has PolicyDefinitionList, it's a list of policy.
 A single element of PolicyDefinitionList has a statement part that combines conditions with an action.


## Definition Steps

These are steps to define policy:

1. define DefinedSets
  1. define PrefixSets
  1. define NeighborSets
1.  define BgpDefinedSets
  1. define CommunitySets
  1. define ExtCommunitySets
  1. define AsPathSetList
1. define PolicyDefinitions
1. attach policies to a neighbor

----

### 1. Defining DefinedSets
DefineSets has prefix information and neighbor information in PrefixSets and NeighborSets section, and GoBGP uses these information to evaluate routes.
Defining DefinedSets is needed at first.
PrefixSets and NeighborSets section are prefix match part and neighbor match part.

- DefinedSets example

 ```
 # prefix match part
  [DefinedSets.PrefixSets]
    [[DefinedSets.PrefixSets.PrefixSetList]]
      PrefixSetName = "ps1"
      [[DefinedSets.PrefixSets.PrefixSetList.PrefixList]]
        IpPrefix = "10.33.0.0/16"
        MasklengthRange = "21..24"

 # neighbor match part
  [DefinedSets.NeighborSets]
    [[DefinedSets.NeighborSetList]]
      NeighborSetName = "ns1"
      [[DefinedSets.NeighborSetList.NeighborInfoList]]
        Address = "10.0.255.1"
 ```

  ----

 #### PrefixSets
 PrefixSets has PrefixSetList, and PrefixSetList has PrefixList as its element. PrefixList has prefix information to match destination's address and we can specify route's NLRI inside.

 PrefixSetList has 3 elements.

 | Element         |Description        | Example       | Optional   |
 |-----------------|-------------------|---------------|------------|
 | PrefixSetName   | name of PrefixSet | "ps1"         |            |
 | IpPrefix        | prefix value      | "10.33.0.0/16"|            |
 | MasklengthRange | range of length   | "21..24"      | Yes        |


 ##### Examples
 - example 1
   - Match routes whose high order 2 octets of NLRI is 10.33 and its prefix length is between from 21 to 24

  ```
  # example 1
  [DefinedSets.PrefixSets]
    [[DefinedSets.PrefixSets.PrefixSetList]]
      PrefixSetName = "ps1"
      [[DefinedSets.PrefixSets.PrefixSetList.PrefixList]]
        IpPrefix = "10.33.0.0/16"
        MasklengthRange = "21..24"
  ```

   - If you define a PrefixList that doesn't have MasklengthRange, it matches routes that have just 10.33.0.0/16 as NLRI.


 - example 2
   - If you want to evaluate multiple routes with a single PrefixSetList, you can do this by adding an another PrefixList like this:

  ```
  # example 2
  [DefinedSets.PrefixSets]
    [[DefinedSets.PrefixSets.PrefixSetList]]
      PrefixSetName = "ps1"
      [[DefinedSets.PrefixSets.PrefixSetList.PrefixList]]
        IpPrefix = "10.33.0.0/16"
        MasklengthRange = "21..24"
      [[DefinedSets.PrefixSets.PrefixSetList.PrefixList]]
        IpPrefix = "10.50.0.0/16"
        MasklengthRange = "21..24"
  ```
   - This prefix match checks if a route has 10.33.0.0/21 to 24 **or** 10.50.0.0/21 to 24.


 - example 3
   - PrefixSetName under PrefixSetList is reference to a single PrefixSet.
   - If you want to add different PrefixSet more, you can add other blocks that form the same structure with example 1.

  ```
  # example 3
  [DefinedSets.PrefixSets]
    # PrefixSetList
    [[DefinedSets.PrefixSets.PrefixSetList]]
      PrefixSetName = "ps1"
      [[DefinedSets.PrefixSets.PrefixSetList.PrefixList]]
        IpPrefix = "10.33.0.0/16"
        MasklengthRange = "21..24"
    # another PrefixSetList
    [[DefinedSets.PrefixSets.PrefixSetList]]
      PrefixSetName = "ps2"
      [[DefinedSets.PrefixSets.PrefixSetList.PrefixList]]
        IpPrefix = "10.50.0.0/16"
        MasklengthRange = "21..24"
  ```

  ----

 #### NeighborSets

 NeighborSets has NeighborSetList, and NeighborSetList has NeighborInfoList as its element and NeighborInfoList has neighbor information to match the sender of the routes.
 It is necessary to specify a neighbor address in NeighborInfoList.

 NeighborSetList has 2 elements.

 | Element         |Description          | Example      | Optional   |
 |-----------------|---------------------|--------------|------------|
 | NeighborSetName | name of NeighborSet | "ns1"        |            |
 | Address         | neighbor's address  | "10.0.255.1" |            |

 ##### Examples

 - example 1
   - Match routes which come from the neighbor 10.0.255.1

  ```
  # example 1
  [DefinedSets.NeighborSets]
    [[DefinedSets.NeighborSets.NeighborSetList]]
      NeighborSetName = "ns1"
      [[DefinedSets.NeighborSets.NeighborSetList.NeighborInfoList]]
        Address = "10.0.255.1"
  ```

 - example 2
   - Match routes which come from the neighbor 10.0.255.2

  ```
  # example 2
  [DefinedSets.NeighborSets]
    [[DefinedSets.NeighborSets.NeighborSetList]]
      NeighborSetName = "ns2"
      [[DefinedSets.NeighborSets.NeighborSetList.NeighborInfoList]]
        Address = "10.0.255.2"
  ```

 - example 3
    - As with PrefixSetList, NeighborSetList can have multiple NeighborInfoList like this.
    - This example checks if a route comes from neighbor 10.0.255.1 **or** 10.0.255.2.

  ```
  # example 3
  [DefinedSets.NeighborSets]
    [[DefinedSets.NeighborSets.NeighborSetList]]
      NeighborSetName = "ns3"
      [[DefinedSets.NeighborSets.NeighborSetList.NeighborInfoList]]
        Address = "10.0.255.1"
      [[DefinedSets.NeighborSets.NeighborSetList.NeighborInfoList]]
        Address = "10.0.255.2"
  ```

---

### 2. Defining BgpDefinedSets

BgpDefinedSets has Community information, Extended Community information and AS_PATH information in each Sets section respectively. And it is a child element of DefinedSets.
CommunitySets, ExtCommunitySets and AsPathSets section are each match part.

- BgpDefinedSets example

 ```
  [DefinedSets.BgpDefinedSets]
      # Community match part
    [DefinedSets.BgpDefinedSets.CommunitySets]
      [[DefinedSets.BgpDefinedSets.CommunitySets.CommunitySetList]]
        CommunitySetName = "community1"
        [[DefinedSets.BgpDefinedSets.CommunitySets.CommunitySetList.CommunityList]]
          Community = "65100:10"
      # Extended Community match part
    [DefinedSets.BgpDefinedSets.ExtCommunitySets]
      [[DefinedSets.BgpDefinedSets.ExtCommunitySets.ExtCommunitySetList]]
        ExtCommunitySetName = "ecommunity1"
        [[DefinedSets.BgpDefinedSets.ExtCommunitySets.ExtCommunitySetList.ExtCommunityList]]
          ExtCommunity = "RT:65001:200"
      # AS_PATH match part
    [DefinedSets.BgpDefinedSets.AsPathSets]
      [[DefinedSets.BgpDefinedSets.AsPathSets.AsPathSetList]]
        AsPathSetName = "aspath1"
        [[DefinedSets.BgpDefinedSets.AsPathSets.AsPathSetList.AsPathList]]
          AsPath = "^65100"
 ```

  ----

 #### CommunitySets
 CommunitySets has CommunitySetList, and CommunitySetList has CommunityList. The values are used to evaluate communities held by the destination.

 CommunitySetList has 2 elements.

 | Element          | Description             | Example      | Optional |
 |------------------|-------------------------|--------------|----------|
 | CommunitySetName | name of CommunitySet    | "community1" |          |
 | Community        | community value         | "65100:10"   |          |

 You can use regular expressions to specify community in CommunityList.

 ##### Examples
 - example 1
   - Match routes which has "65100:10" as a community value.

  ```
  # example 1
  [DefinedSets.BgpDefinedSets]
    [DefinedSets.BgpDefinedSets.CommunitySets]
      [[DefinedSets.BgpDefinedSets.CommunitySets.CommunitySetList]]
        CommunitySetName = "community1"
        [[DefinedSets.BgpDefinedSets.CommunitySets.CommunitySetList.CommunityList]]
          Community = "65100:10"
  ```

 - example 2
    - Specifying community by regular expression
    - You can use regular expressions that is available in Golang.

  ```
  # example 2
  [DefinedSets.BgpDefinedSets]
    [DefinedSets.BgpDefinedSets.CommunitySets]
      [[DefinedSets.BgpDefinedSets.CommunitySets.CommunitySetList]]
        CommunitySetName = "community2"
        [[DefinedSets.BgpDefinedSets.CommunitySets.CommunitySetList.CommunityList]]
          Community = 6[0-9]+:[0-9]+"
  ```
   ----

 #### ExtCommunitySets
 ExtCommunitySets has ExtCommunitySetList, and ExtCommunitySetList has ExtCommunityList. The values are used to evaluate extended communities held by the destination.

 ExtCommunitySetList has 2 elements.

 | Element             | Description                | Example          | Optional |
 |---------------------|----------------------------|------------------|----------|
 | ExtCommunitySetName | name of ExtCommunitySet    | "ecommunity1"    |          |
 | ExtCommunity        | extended community value   | "RT:65001:200"   |          |

 You can use regular expressions to specify extended community in ExtCommunityList.
 However, the first one element separated by (part of "RT") does not support to the regular expression.
 part of "RT" indicate sub type of extended community and using sub type as follows:

  - RT: mean the route target.
  - SoO: mean the site of origin(route origin).


 ##### Examples
 - example 1
      - Match routes which has "RT:65001:200" as a extended community value.

  ```
  # example 1
  [DefinedSets.BgpDefinedSets]
    [DefinedSets.BgpDefinedSets.ExtCommunitySets]
      [[DefinedSets.BgpDefinedSets.ExtCommunitySets.ExtCommunitySetList]]
        ExtCommunitySetName = "ecommunity1"
        [[DefinedSets.BgpDefinedSets.ExtCommunitySets.ExtCommunitySetList.ExtCommunityList]]
          ExtCommunity = "RT:65001:200"
  ```

 - example 2
    - Specifying extended community by regular expression
    - You can use regular expressions that is available in Golang.

  ```
  # example 2
  [DefinedSets.BgpDefinedSets]
    [DefinedSets.BgpDefinedSets.ExtCommunitySets]
      [[DefinedSets.BgpDefinedSets.ExtCommunitySets.ExtCommunitySetList]]
        ExtCommunitySetName = "ecommunity1"
        [[DefinedSets.BgpDefinedSets.ExtCommunitySets.ExtCommunitySetList.ExtCommunityList]]
          ExtCommunity = "RT:6[0-9]+:[0-9]+"
  ```

   ----


 #### AsPathSets
 AsPathSets has AsPathSetList, and AsPathSetList has AsPathList. The numbers are used to evaluate AS numbers in the destination's AS_PATH attribute.

   AsPathSetList has 2 elements.

 | Element          | Description       | Example    | Optional |
 |------------------|-------------------|------------|----------|
 | AsPathSetName    | name of AsPathSet | "aspath1"  |          |
 | AsPathSet        | as path value     | "^65100"   |          |

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
    [DefinedSets.BgpDefinedSets.AsPathSets]
      [[DefinedSets.BgpDefinedSets.AsPathSets.AsPathSetList]]
        AsPathSetName = "aspath1"
        [[DefinedSets.BgpDefinedSets.AsPathSets.AsPathSetList.AsPathList]]
          AsPath = "^65100"
  ```

---

### 3. Defining PolicyDefinitions
PolicyDefinitions has PolicyDefinitionList, and PolicyDefinitionList consists of condition and action of the policy. The condition part evaluates routes from neighbors and applies action if the routes match conditions. You can use DefinedSets above and other conditions to specify conditions in the PolicyDefinitions.

PolicyDefinitions has PolicyDefinition as its element and the PolicyDefinition is a policy itself.
You can write condition and action under Statements.

 - an example of PolicyDefinitions

 ```
[PolicyDefinitions]
  [[PolicyDefinitions.PolicyDefinitionList]]
    Name = "example-policy"
    [PolicyDefinitions.PolicyDefinitionList.Statements]
      [[PolicyDefinitions.PolicyDefinitionList.Statements.StatementList]]
        Name = "statement1"
        [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions]
          [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.MatchPrefixSet]
            PrefixSet = "ps1"
            MatchSetOptions = 0
          [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.MatchNeighborSet]
            NeighborSet = "ns1"
            MatchSetOptions = 1
          [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.BgpConditions]
            [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.BgpConditions.MatchCommunitySet]
              CommunitySet = "community1"
              MatchSetOptions = 0
            [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.BgpConditions.MatchExtCommunitySet]
              ExtCommunitySet = "ecommunity1"
              MatchSetOptions = 0
            [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.BgpConditions.MatchAsPathSet]
              AsPathSet = "aspath1"
              MatchSetOptions = 0
            [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.BgpConditions.AsPathLength]
              Operator = "eq"
              Value = 2
        [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Actions]
          [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Actions.RouteDisposition]
            AcceptRoute = true
          [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Actions.BgpActions]
            SetMed = "-200"
            [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Actions.BgpActions.SetAsPathPrepend]
              As = "65005"
              RepeatN = 5
            [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Actions.BgpActions.SetCommunity]
              Options = "ADD"
              [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Actions.BgpActions.SetCommunity.SetCommunityMethod]
                Communities = ["65100:20"]

 ```

 The elements of PolicyDefinitionList are as follows:

  - PolicyDefinitions.PolicyDefinitionList

 | Element | Description   | Example          |
 |---------|---------------|------------------|
 | name    | policy's name | "example-policy" |

  - PolicyDefinitionsPolicyDefinitionList.StatementList

 | Element | Description       | Example        |
 |---------|-------------------|----------------|
 | name    | statements's name | "statement1"   |

  - PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.MatchPrefixSet

 | Element          | Description                                                               | Example |
 |------------------|---------------------------------------------------------------------------|---------|
 | PrefixSet        | name for DefinedSets.PrefixSets.PrefixSetList that is used in this policy | "ps1"   |
 | MatchSetOptions  | option for the check:<br> 0 means **ANY**,<br>  1 means **INVERT**        | 0       |

  - PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.MatchNegihborSet

 | Element          | Description                                                                   | Example |
 |------------------|-------------------------------------------------------------------------------|---------|
 | NegihborSet      | name for DefinedSets.NeighborSets.NeighborSetList that is used in this policy | "ns1"   |
 | MatchSetOptions  | option for the check:<br> 0 means **ANY**,<br>  1 means **INVERT**            | 1       |

  - PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.BgpConditions.MatchCommunitySet

 | Element          | Description                                                                                    | Example        |
 |------------------|------------------------------------------------------------------------------------------------|----------------|
 | CommunitySet     | name for DefinedSets.BgpDefinedSets.CommunitySets.CommunitySetList that is used in this policy | "community1"   |
 | MatchSetOptions  | option for the check:<br> 0 means **ANY**,<br> 1 means **ALL**,<br> 2 means **INVERT**         | 0              |

  - PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.BgpConditions.MatchExtCommunitySet

 | Element          | Description                                                                                          | Example       |
 |------------------|------------------------------------------------------------------------------------------------------|---------------|
 | ExtCommunitySet  | name for DefinedSets.BgpDefinedSets.ExtCommunitySets.ExtCommunitySetList that is used in this policy | "ecommunity1" |
 | MatchSetOptions  | option for the check:<br> 0 means **ANY**,<br> 1 means **ALL**,<br> 2 means **INVERT**               | 1             |

  - PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.BgpConditions.MatchAsPathSet

 | Element          | Description                                                                                    | Example   |
 |------------------|------------------------------------------------------------------------------------------------|-----------|
 | AsPathSet        | name for DefinedSets.BgpDefinedSets.AsPathSets.AsPathSetList that is used in this policy       | "aspath1" |
 | MatchSetOptions  | option for the check:<br> 0 means **ANY**,<br> 1 means **ALL**,<br> 2 means **INVERT**         | 0         |

  - PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.BgpConditions.AsPathLength

 | Element  | Description                                                                                        | Example |
 |----------|----------------------------------------------------------------------------------------------------|---------|
 | Operator | operator to compare the length of AS number in AS_PATH attribute. <br> "eq","ge","le" can be used. <br> "eq" means that length of AS number is equal to Value element <br> "ge" means that length of AS number is equal or greater than the Value element <br> "le" means that length of AS number is equal or smaller than the Value element| "eq"    |
 | Value    | value used to compare with the length of AS number in AS_PATH attribute                            | 2       |

  - PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Actions.RouteDisposition

 | Element     | Description                                                                       | Example |
 |-------------|-----------------------------------------------------------------------------------|---------|
 | AcceptRoute | action to accept the route if matches conditions. If true, this route is accepted | true    |

  - PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Actions.BgpActions

 | Element | Description                                                                           | Example |
 |---------|---------------------------------------------------------------------------------------|---------|
 | SetMed  | SetMed used to change the med value of the route. <br> If only numbers have been specified, replace the med value of route.<br> if number and operater(+ or -) have been specified, adding or subtracting the med value of route. | "-200"    |

  - PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Actions.BgpActions.SetCommunity

 | Element     | Description                                                                      | Example    |
 |-------------|----------------------------------------------------------------------------------|------------|
 | Options     | operator to manipulate Community attribute in the route                          | "ADD"      |
 | Communities | communities used to manipulate the route's community accodriong to Options below | "65100:20" |

  - PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Actions.BgpActions.SetAsPathPrepend

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
[PolicyDefinitions]
  [[PolicyDefinitions.PolicyDefinitionList]]
    Name = "policy1"
    [PolicyDefinitions.PolicyDefinitionList.Statements]
      [[PolicyDefinitions.PolicyDefinitionList.Statements.StatementList]]
        Name = "statement1"
        [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions]
          [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.MatchPrefixSet]
            PrefixSet = "ps1"
            MatchSetOptions = 0
          [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.MatchNeighborSet]
            NeighborSet = "ns1"
            MatchSetOptions = 0
        [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Actions]
          [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Actions.RouteDisposition]
            RejectRoute = true
 ```

 - example 2
  - PolicyDefinition has two statements

 ```
 # example 2
[PolicyDefinitions]
  [[PolicyDefinitions.PolicyDefinitionList]]
    Name = "policy1"
    [PolicyDefinitions.PolicyDefinitionList.Statements]
      # first statement - (1)
      [[PolicyDefinitions.PolicyDefinitionList.Statements.StatementList]]
        Name = "statement1"
        [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions]
          [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.MatchPrefixSet]
            PrefixSet = "ps1"
            MatchSetOptions = 0
          [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.MatchNeighborSet]
            NeighborSet = "ns1"
            MatchSetOptions = 0
        [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Actions]
          [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Actions.RouteDisposition]
            RejectRoute = true
      # second statement - (2)
      [[PolicyDefinitions.PolicyDefinitionList.Statements.StatementList]]
        Name = "statement2"
        [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions]
          [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.MatchPrefixSet]
            PrefixSet = "ps2"
            MatchSetOptions = 0
          [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.MatchNeighborSet]
            NeighborSet = "ns2"
            MatchSetOptions = 0
        [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Actions]
          [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Actions.RouteDisposition]
            RejectRoute = true
 ```
  - if a route matches the condition inside the first statement(1), GoBGP applies its action and quits the policy evaluation.


 - example 3
  - If you want to add other policies, just add PolicyDefinitionList block following the first one like this

 ```
 # example 3
 # first policy
[PolicyDefinitions]
  [[PolicyDefinitions.PolicyDefinitionList]]
    Name = "policy1"
    [PolicyDefinitions.PolicyDefinitionList.Statements]
      [[PolicyDefinitions.PolicyDefinitionList.Statements.StatementList]]
        Name = "statement1"
        [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions]
          [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.MatchPrefixSet]
            PrefixSet = "ps1"
            MatchSetOptions = 0
          [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.MatchNeighborSet]
            NeighborSet = "ns1"
            MatchSetOptions = 0
        [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Actions]
          [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Actions.RouteDisposition]
            RejectRoute = true
  # second policy
  [[PolicyDefinitions.PolicyDefinitionList]]
    Name = "policy2"
    [PolicyDefinitions.PolicyDefinitionList.Statements]
      [[PolicyDefinitions.PolicyDefinitionList.Statements.StatementList]]
        Name = "statement2"
        [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions]
          [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.MatchPrefixSet]
            PrefixSet = "ps2"
            MatchSetOptions = 0
          [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.MatchNeighborSet]
            NeighborSet = "ns2"
            MatchSetOptions = 0
        [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Actions]
          [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Actions.RouteDisposition]
            RejectRoute = true
 ```

 - example 4
  - This PolicyDefinition has multiple conditions including BgpConditions as follows:
    - PrefixSet: *ps1*
    - NeighborSet: *ns1*
    - CommunitySet: *community1*
    - ExtCommunitySet: *ecommunity1*
    - AsPathSet: *aspath1*
    - AsPath length: *equal 2*

  - If a route matches all these conditions, the route is accepted and added community "65100:20" and subtracted 200 from med value and prepended 65005 five times in its AS_PATH attribute.

 ```
 # example 4
[PolicyDefinitions]
  [[PolicyDefinitions.PolicyDefinitionList]]
    Name = "policy1"
    [PolicyDefinitions.PolicyDefinitionList.Statements]
      [[PolicyDefinitions.PolicyDefinitionList.Statements.StatementList]]
        Name = "statement1"
        [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions]
          [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.MatchPrefixSet]
            PrefixSet = "ps1"
            MatchSetOptions = 0
          [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.MatchNeighborSet]
            NeighborSet = "ns1"
            MatchSetOptions = 0
          [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.BgpConditions]
            [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.BgpConditions.MatchCommunitySet]
              CommunitySet = "community1"
              MatchSetOptions = 0
            [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.BgpConditions.MatchExtCommunitySet]
              ExtCommunitySet = "ecommunity1"
              MatchSetOptions = 0
            [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.BgpConditions.MatchAsPathSet]
              AsPathSet = "aspath1"
              MatchSetOptions = 0
            [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.BgpConditions.AsPathLength]
              Operator = "eq"
              Value = 2
        [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Actions]
          [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Actions.RouteDisposition]
            AcceptRoute = true
          [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Actions.BgpActions]
            SetMed = "-200"
            [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Actions.BgpActions.SetAsPathPrepend]
              As = "65005"
              RepeatN = 5
            [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Actions.BgpActions.SetCommunity]
              Options = "ADD"
              [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Actions.BgpActions.SetCommunity.SetCommunityMethod]
                Communities = ["65100:20"]
 ```


---

### 4. Attaching policy
You can use policies defined above as import or export or distribtue policy by
attaching them to neighbors.

   Note: The distribute policy is applied only when the peer is Route Server client.

To attach policies to neighbors, you need to add policy's name to Neighbors.NeighborList.ApplyPolicy in the neighbor's setting.
This example attatches *policy1* to import policy and *policy2* to export policy and *policy3* is used as the distribute policy.

```
[Neighbors]
  [[Neighbors.NeighborList]]
    [Neighbors.NeighborList.NeighborConfig]
      NeighborAddress = "10.0.255.2"
      PeerAs = 65002
    [Neighbors.NeighborList.RouteServer]
      RouteServerClient = true
    [Neighbors.NeighborList.ApplyPolicy]
      [Neighbors.NeighborList.ApplyPolicy.ApplyPolicyConfig]
        ImportPolicy = ["policy1"]
        ExportPolicy = ["policy2"]
        DistributedPolicy = ["policy3"]
        DefaultImportPolicy = 0
        DefaultExportPolicy = 0
        DefaultDistributePolicy = 0
```

Neighbors.NeighborList has a section to specify policies and the section's name is ApplyPolicy.
The ApplyPolicy has 6 elements.

| Element                 | Description                                                                                 | Example    |
|-------------------------|---------------------------------------------------------------------------------------------|------------|
| ImportPolicy            | PolicyDefinitions.PolicyDefinitionList.name for import policy                               | "policy1"  |
| ExportPolicy            | PolicyDefinitions.PolicyDefinitionList.name for export policy                               | "policy2"  |
| DistributedPolicy       | PolicyDefinitions.PolicyDefinitionList.name for distribute policy                           | "policy3"  |
| DefaultImportPolicy     | action when the route doesn't match any policy:<br> 0 means import,<br>  1 means reject     | 0          |
| DefaultExportPolicy     | action when the route doesn't match any policy:<br> 0 means export,<br>  1 means discard    | 0          |
| DefaultDistributePolicy | action when the route doesn't match any policy:<br> 0 means distribute,<br>  1 means reject | 0          |
