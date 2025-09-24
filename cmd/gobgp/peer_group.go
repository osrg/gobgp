package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/spf13/cobra"
)

func newPeerGroupCmd() *cobra.Command {
	pgCmdImpl := &cobra.Command{}

	policyCmd := &cobra.Command{
		Use: cmdPolicy,
		Run: func(cmd *cobra.Command, args []string) {
			key := oc.NewPeerGroupPolicyAssignmentKeyFromName(args[0])
			for _, v := range []string{cmdImport, cmdExport} {
				if err := showNeighborPolicy(key, v, 4); err != nil {
					exitWithError(err)
				}
			}
		},
	}
	pgCmdImpl.AddCommand(policyCmd)

	pgCmd := &cobra.Command{
		Use:     cmdPeerGroup,
		Aliases: []string{cmdPeerGroupShort},

		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			if len(args) < 2 {
				var pgName string
				if len(args) == 1 {
					pgName = args[0]
				}
				showPeerGroups(pgName)
			} else {
				args = append(args[1:], args[0])
				pgCmdImpl.SetArgs(args)
				err = pgCmdImpl.Execute()
			}
			if err != nil {
				exitWithError(err)
			}
			return nil
		},
	}

	return pgCmd
}

func showPeerGroups(name string) {
	pgs, err := getPeerGroups(name)
	if err != nil {
		exitWithError(err)
	}

	if globalOpts.Json {
		j, _ := json.Marshal(pgs)
		fmt.Println(string(j))
		return
	}

	sort.Slice(pgs, func(i, j int) bool {
		return pgs[i].Conf.PeerGroupName < pgs[j].Conf.PeerGroupName
	})

	nameColLen := 10
	for _, pg := range pgs {
		if len(pg.Conf.PeerGroupName) > nameColLen {
			nameColLen = len(pg.Conf.PeerGroupName)
		}
	}

	fmtstr := "%-" + strconv.Itoa(nameColLen) + "s %8s %5s %s\n"
	fmt.Printf(fmtstr, "PeerGroup", "Type", "AS", "Info")
	for _, pg := range pgs {
		info := make([]string, 0, 2)
		if pg.Info.LocalAsn != pg.Info.PeerAsn {
			info = append(info, fmt.Sprintf("local-as %d", pg.Info.LocalAsn))
		}

		if pg.RouteReflector != nil && pg.RouteReflector.RouteReflectorClient {
			info = append(info, fmt.Sprintf("route-reflector-client %s", pg.RouteReflector.RouteReflectorClusterId))
		} else if pg.RouteServer != nil && pg.RouteServer.RouteServerClient {
			info = append(info, "route-server-client")
		}

		fmt.Printf(
			fmtstr,
			pg.Conf.PeerGroupName,
			api.PeerType_name[int32(pg.Info.Type)],
			fmt.Sprint(pg.Info.PeerAsn),
			strings.Join(info, ", "),
		)
	}
}

func getPeerGroups(name string) ([]*api.PeerGroup, error) {
	stream, err := client.ListPeerGroup(ctx, &api.ListPeerGroupRequest{
		PeerGroupName: name,
	})
	if err != nil {
		return nil, err
	}

	l := make([]*api.PeerGroup, 0, 1024)
	for {
		r, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		l = append(l, r.PeerGroup)
	}
	if name != "" && len(l) == 0 {
		return l, fmt.Errorf("not found peer group %s", name)
	}
	return l, err
}
