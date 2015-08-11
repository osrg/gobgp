# Policy configuration

This page explains GoBGP policy feature for controlling the route
advertisement. It might be called Route Map in other BGP
implementations.

We explain the overview firstly, then the details, 

## Prerequisites

Assumed that you finished [Getting Started](https://github.com/osrg/gobgp/blob/master/docs/sources/getting-started.md). Also [Route Server](https://github.com/osrg/gobgp/blob/master/docs/sources/route-server.md) is plus because we use Route Server setup for an example configuration.

## Overview

### How policies works with RIBs

There are three categories for policies: **Import**, **Export** and **In** policies.

**Import** and **Export** policies are defined with respect to the
local routing table. The **Import** policy defines what routes will be
imported into its local RIBs. The **Export** policy defines what
routes will be exported from its local RIBs. **In** polices are
defined with respect to a peer in only Route Server setup. The **In**
policy defines what routes will go to other peers' local routing tables.

The following figure shows how **Import**, **Export**, and **In**
policies work with RIBs in Route Server setup.

![Announcement processing model implemented by the Route Server](./policy-rs.png)

### What's a policy?

A policy consists of statements. Each statement has condition(s) and action(s).

Conditions are categorized into attributes below:

- prefix
- neighbor
- aspath
- aspath length
- community
- extended community

Actions are categorized into attributes below:

- accept or reject
- add/replace/remove community or remove all communities
- add/subtract or replace MED value
- prepend AS number in the AS_PATH attribute

All the condition(s) in the statement are true, the action(s) in the statement are executed.

A condition can have multiple values. For example, you can define a prefix
condition that has 10.20.0.0/16, 10.30.3.0/24, and 10.30.4.0/24. You can specify
how these values are used to decide whether the condition is true of
false. In this case, you can specify either:

- true if a route matches any of 10.20.0.0/16, 10.30.3.0/24, and 10.30.4.0/24.
- true if a route matches none of 10.20.0.0/16, 10.30.3.0/24, and 10.30.4.0/24.

The details will be explained in the following sessions. If you
quickly check out what policy configuration looks like, skip the next
sessions to go to the last session.

## The details of steps to define policies

GoBGP's configuration file has two parts named **DefinedSets** and **PolicyDefinitions** as its policy configuration. **DefinedSets** part defines conditions. **PolicyDefinitions** defines policies based on actions and these conditions.


 - DefinedSets

 A single DefinedSets entry has prefix match that is named PrefixSets and neighbor match part that is named NeighborSets. It also has BgpDefinedSets, a subset of DefinedSets that defines conditions referring to BGP attributes such as aspath. This DefinedSets has a name and it's used to refer to DefinedSets items from outside.

 - PolicyDefinitions

 PolicyDefinitions has PolicyDefinitionList, it's a list of policy.
 A single element of PolicyDefinitionList has a statement part that combines conditions with an action.


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
 PrefixSets has PrefixSetList, and PrefixSetList has PrefixSetName and PrefixList as its element. prefix information to match destination's address and we can specify route's NLRI inside. PrefixSetList is used as a condition.

 **PrefixSetList** has 1 element and list of subelement.

 | Element         | Description                        | Example       | Optional   |
 |-----------------|------------------------------------|---------------|------------|
 | PrefixSetName   | name of PrefixSet                  | "ps1"         |            |
 | PrefixList      | list of prefix and range of length |               |            |

 **PrefixLlist** has 2 elements.

 | Element         | Description       | Example       | Optional   |
 |-----------------|-------------------|---------------|------------|
 | IpPrefix        | prefix value      | "10.33.0.0/16"|            |
 | MasklengthRange | range of length   | "21..24"      | Yes        |


 ##### Examples
 - example 1
   - Match routes whose high order 2 octets of NLRI is 10.33 and its prefix length is between from 21 to 24
   - If you define a PrefixList that doesn't have MasklengthRange, it matches routes that have just 10.33.0.0/16 as NLRI.

  ```
  # example 1
  [DefinedSets.PrefixSets]
    [[DefinedSets.PrefixSets.PrefixSetList]]
      PrefixSetName = "ps1"
      [[DefinedSets.PrefixSets.PrefixSetList.PrefixList]]
        IpPrefix = "10.33.0.0/16"
        MasklengthRange = "21..24"
  ```


 - example 2
   - If you want to evaluate multiple routes with a single PrefixSetList, you can do this by adding an another PrefixList like this:
   - This PrefixSetList match checks if a route has 10.33.0.0/21 to 24 or 10.50.0.0/21 to 24.

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

 NeighborSets has NeighborSetList, and NeighborSetList has NeighborSetName and NeighborInfoList as its element. neighbor information to match the sender of the routes.It is necessary to specify a neighbor address in NeighborInfoList. NeighborSetList is used as a condition.

 **NeighborSetList** has 1 element and list of subelement.

 | Element          |Description                | Example      | Optional   |
 |------------------|---------------------------|--------------|------------|
 | NeighborSetName  | name of NeighborSet       | "ns1"        |            |
 | NeighborInfoList | list of neighbor address  |              |            |

 **NeighborInfoList** has 1 element.

 | Element         |Description          | Example      | Optional   |
 |-----------------|---------------------|--------------|------------|
 | Address         | neighbor address    | "10.0.255.1" |            |

 ##### Examples

 - example 1
  ```
  # example 1
  [DefinedSets.NeighborSets]
    [[DefinedSets.NeighborSets.NeighborSetList]]
      NeighborSetName = "ns1"
      [[DefinedSets.NeighborSets.NeighborSetList.NeighborInfoList]]
        Address = "10.0.255.1"
  ```

 - example 2
    - As with PrefixSetList, NeighborSetList can have multiple NeighborInfoList like this.

  ```
  # example 2
  [DefinedSets.NeighborSets]
    [[DefinedSets.NeighborSets.NeighborSetList]]
      NeighborSetName = "ns2"
      [[DefinedSets.NeighborSets.NeighborSetList.NeighborInfoList]]
        Address = "10.0.255.1"
      [[DefinedSets.NeighborSets.NeighborSetList.NeighborInfoList]]
        Address = "10.0.255.2"
  ```

 - example 3
    - As with PrefixSetList, multiple NeighborSetLists can be defined. 
 
  ```
  # example 3
  [DefinedSets.NeighborSets]
    [[DefinedSets.NeighborSets.NeighborSetList]]
      NeighborSetName = "ns1"
      [[DefinedSets.NeighborSets.NeighborSetList.NeighborInfoList]]
        Address = "10.0.255.1"
    # another NeighborSetList
    [[DefinedSets.NeighborSets.NeighborSetList]]
      NeighborSetName = "ns2"
      [[DefinedSets.NeighborSets.NeighborSetList.NeighborInfoList]]
        Address = "10.0.254.1"
  ```

---

### 2. Defining BgpDefinedSets

BgpDefinedSets has Community information, Extended Community
information and AS_PATH information in each Sets section
respectively. And it is a child element of DefinedSets.
CommunitySets, ExtCommunitySets and AsPathSets section are each match
part. Like PrefixSets and NeighborSets, Each can have multple sets and each set can have multiple values.

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
 CommunitySets has CommunitySetList, and CommunitySetList has CommunitySetName and CommunityList as its element. The Community value are used to evaluate communities held by the destination.

 **CommunitySetList** has 1 element and list of subelement.

 | Element          | Description             | Example      | Optional |
 |------------------|-------------------------|--------------|----------|
 | CommunitySetName | name of CommunitySet    | "community1" |          |
 | CommunityList    | list of community value |              |          |

 **CommunityList** has 1 element.

 | Element          | Description             | Example      | Optional |
 |------------------|-------------------------|--------------|----------|
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
    - You can use regular expressions based on POSIX 1003.2 regular expressions.

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
 ExtCommunitySets has ExtCommunitySetList, and ExtCommunitySetList has ExtCommunitySetName and ExtCommunityList as its element. The values are used to evaluate extended communities held by the destination.

 **ExtCommunitySetList** has 1 element and list of subelement.

 | Element             | Description                        | Example          | Optional |
 |---------------------|------------------------------------|------------------|----------|
 | ExtCommunitySetName | name of ExtCommunitySet            | "ecommunity1"    |          |
 | ExtCommunityList    | list of extended community value   |　　　             |          |

 **ExtCommunityList** has 1 element.

 | Element             | Description                | Example          | Optional |
 |---------------------|----------------------------|------------------|----------|
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
 AsPathSets has AsPathSetList, and AsPathSetList has AsPathSetName and AsPathList as its element. The numbers are used to evaluate AS numbers in the destination's AS_PATH attribute.

 **AsPathSetList** has 1 element and list of subelement.

 | Element          | Description               | Example    | Optional |
 |------------------|---------------------------|------------|----------|
 | AsPathSetName    | name of AsPathSet         | "aspath1"  |          |
 | AsPathSet        | list of as path value     |            |          |

 **AsPathList** has 1 elements.

 | Element          | Description       | Example    | Optional |
 |------------------|-------------------|------------|----------|
 | AsPathSet        | as path value     | "^65100"   |          |

 The AS path regular expression is compatible with [Quagga](http://www.nongnu.org/quagga/docs/docs-multi/AS-Path-Regular-Expression.html) and Cisco. Some examples follow:

   - From: "^65100" means the route is passed from AS 65100 directly.
   - Any: "65100" means the route comes through AS 65100.
   - Origin: "65100$" means the route is originated by AS 65100.
   - Only: "^65100$" means the route is originated by AS 65100 and comes from it directly.
   - ^65100_65001
   - 65100_[0-9]+_.*$
   - ^6[0-9]_5.*_65.?00$

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

  - example 2
      - Match routes which come Origin AS 65100 and use regular expressions to other AS.

  ```
  # example 2
  [DefinedSets.BgpDefinedSets]
    [DefinedSets.BgpDefinedSets.AsPathSets]
      [[DefinedSets.BgpDefinedSets.AsPathSets.AsPathSetList]]
        AsPathSetName = "aspath2"
        [[DefinedSets.BgpDefinedSets.AsPathSets.AsPathSetList.AsPathList]]
          AsPath = "[0-9]+_65[0-9]+_65100$"
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


 - Execution condition of Action

 Action statement is executed when the result of each Condition, including MatchSetOption is all true.
 **MatchSetOptions** is defined how to determine the match result, in the condition with multiple evaluation set as follows:

 | Value  | Description                                                               |
 |--------|---------------------------------------------------------------------------|
 | ANY    | match is true if given value matches any member of the defined set        |
 | ALL    | match is true if given value matches all members of the defined set       |
 | INVERT | match is true if given value does not match any member of the defined set |



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
You can use policies defined above as Import or Export or In policy by
attaching them to neighbors.

   Note: The In policy is applied only when the peer is Route Server client.

To attach policies to neighbors, you need to add policy's name to Neighbors.NeighborList.ApplyPolicy in the neighbor's setting.
This example attatches *policy1* to Import policy and *policy2* to Export policy and *policy3* is used as the In policy.

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
        InPolicy = ["policy3"]
        DefaultImportPolicy = 0
        DefaultExportPolicy = 0
        DefaultInPolicy = 0
```

Neighbors.NeighborList has a section to specify policies and the section's name is ApplyPolicy.
The ApplyPolicy has 6 elements.

| Element                 | Description                                                                                 | Example    |
|-------------------------|---------------------------------------------------------------------------------------------|------------|
| ImportPolicy            | PolicyDefinitions.PolicyDefinitionList.name for Import policy                               | "policy1"  |
| ExportPolicy            | PolicyDefinitions.PolicyDefinitionList.name for Export policy                               | "policy2"  |
| InPolicy       | PolicyDefinitions.PolicyDefinitionList.name for In policy                                    | "policy3"  |
| DefaultImportPolicy     | action when the route doesn't match any policy:<br> 0 means Import,<br>  1 means reject     | 0          |
| DefaultExportPolicy     | action when the route doesn't match any policy:<br> 0 means Export,<br>  1 means discard    | 0          |
| DefaultInPolicy | action when the route doesn't match any policy:<br> 0 means In,<br>  1 means reject         | 0          |


## Simple configuration example

A policy consists of a match and an action. A match defines if an
action will be applied to a route. For now, GoBGP uses only the source
of a peer and a prefix as match conditions. Only dropping and
accepting are supported as an action.

This example the configuration in [Route
Server](https://github.com/osrg/gobgp/blob/master/docs/sources/route-server.md)
with one more peer (IP:10.0.255.3, AS:65001).

Neighbor 10.0.255.1 advertises 10.33.0.0/16 and 10.3.0.0/16 routes. We
define an import policy for neighbor 10.0.255.2 that drops
10.33.0.0/16 route from Neighbor 10.0.255.1.

```
[Global]
  [Global.GlobalConfig]
    As = 64512
    RouterId = "192.168.255.1"

[Neighbors]
  [[Neighbors.NeighborList]]
    [Neighbors.NeighborList.NeighborConfig]
      NeighborAddress = "10.0.255.1"
      PeerAs = 65001
    [Neighbors.NeighborList.RouteServer]
      [Neighbors.NeighborList.RouteServer.RouteServerConfig]
        RouteServerClient = true

  [[Neighbors.NeighborList]]
    [Neighbors.NeighborList.NeighborConfig]
      NeighborAddress = "10.0.255.2"
      PeerAs = 65002
    [Neighbors.NeighborList.RouteServer]
      [Neighbors.NeighborList.RouteServer.RouteServerConfig]
        RouteServerClient = true
    [Neighbors.NeighborList.ApplyPolicy]
      [Neighbors.NeighborList.ApplyPolicy.ApplyPolicyConfig]
        ImportPolicy = ["pd2"]

  [[Neighbors.NeighborList]]
    [Neighbors.NeighborList.NeighborConfig]
      NeighborAddress = "10.0.255.3"
      PeerAs = 65003
    [Neighbors.NeighborList.RouteServer]
      [Neighbors.NeighborList.RouteServer.RouteServerConfig]
        RouteServerClient = true

[DefinedSets]
  [DefinedSets.PrefixSets]
    [[DefinedSets.PrefixSets.PrefixSetList]]
      PrefixSetName = "ps2"
      [[DefinedSets.PrefixSets.PrefixSetList.PrefixList]]
        IpPrefix = "10.33.0.0/16"
      [[DefinedSets.PrefixSets.PrefixSetList.PrefixList]]
        IpPrefix = "10.50.0.0/16"


  [DefinedSets.NeighborSets]
    [[DefinedSets.NeighborSetList]]
      NeighborSetName = "ns1"
      [[DefinedSets.NeighborSetList.NeighborInfoList]]
        Address = "10.0.255.1"

[PolicyDefinitions]
  [[PolicyDefinitions.PolicyDefinitionList]]
    Name = "pd2"
    [PolicyDefinitions.PolicyDefinitionList.Statements]
      [[PolicyDefinitions.PolicyDefinitionList.Statements.StatementList]]
        Name = "statement1"
        [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions]
          [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.MatchPrefixSet]
            PrefixSet = "ps2"
            MatchSetOptions = 0
          [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Conditions.MatchNeighborSet]
            NeighborSet = "ns1"
            MatchSetOptions = 0
        [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Actions]
          [PolicyDefinitions.PolicyDefinitionList.Statements.StatementList.Actions.RouteDisposition]
            RejectRoute = true
```

Neighbor 10.0.255.2 has pd2 policy. The pd2 policy consists of ps2 prefix match and ns1 neighbor match. The ps2 specifies 10.33.0.0 and 10.50.0.0 address. The ps2 specifies the mask with **MASK** keyword. **MasklengthRange** keyword can specify the range of mask length like ```MasklengthRange 24..26```. The *ns1* specifies neighbor 10.0.255.1.

The pd2 sets multiple condition, This means that only when all match conditions meets, the policy will be applied.

The MatchPrefixSet sets MatchSetOptions to 0. This means that when match to any of PrefixList, the policy will be applied. the policy will be applied to 10.33.0.0/16 or 10.50.0.0 route from neighbor 10.0.255.1.

If the MatchPrefixSet sets MatchSetOptions to 1, It does not match to any of PrefixList, the policy will be applied. the policy will be applied to other than 10.33.0.0/16 or 10.50.0.0 route from neighbor 10.0.255.1

Let's confirm that 10.0.255.1 neighbor advertises two routes.

```
$ gobgp neighbor 10.0.255.1 adj-in
   Network            Next Hop        AS_PATH    Age        Attrs
   10.3.0.0/16        10.0.255.1      [65001]    00:51:57   [{Origin: 0} {Med: 0}]
   10.33.0.0/16       10.0.255.1      [65001]    00:51:57   [{Origin: 0} {Med: 0}]
```

Now let's check out if the policy works as expected.

```
$ gobgp neighbor 10.0.255.2 local
   Network            Next Hop        AS_PATH    Age        Attrs
*> 10.3.0.0/16        10.0.255.1      [65001]    00:49:36   [{Origin: 0} {Med: 0}]
$ gobgp neighbor 10.0.255.3 local
   Network            Next Hop        AS_PATH    Age        Attrs
*> 10.3.0.0/16        10.0.255.1      [65001]    00:49:38   [{Origin: 0} {Med: 0}]
*> 10.33.0.0/16       10.0.255.1      [65001]    00:49:38   [{Origin: 0} {Med: 0}]
```
