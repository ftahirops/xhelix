package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/sensors/lsmaudit"
)

func newPostureCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "posture",
		Short: "Inspect host security posture",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "lsm",
		Short: "Report active LSMs (AppArmor / SELinux / BPF LSM)",
		RunE: func(cmd *cobra.Command, args []string) error {
			st := lsmaudit.Detect()
			fmt.Println("Active LSMs:")
			for _, n := range st.Active {
				fmt.Printf("  - %s\n", n)
			}
			if st.HasAppArmor {
				fmt.Printf("AppArmor mode: %s\n", st.AppArmorMode)
			} else {
				fmt.Println("AppArmor: not present")
			}
			if st.HasSELinux {
				fmt.Printf("SELinux mode: %s\n", st.SELinuxMode)
			} else {
				fmt.Println("SELinux: not present")
			}
			if st.HasBPFLSM {
				fmt.Println("BPF LSM: enabled")
			} else {
				fmt.Println("BPF LSM: NOT ENABLED (xhelix LSM hooks will be degraded)")
			}
			fmt.Printf("\nSummary: %s\n", st.Summary())
			return nil
		},
	})
	return cmd
}
