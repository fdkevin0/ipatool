package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/avast/retry-go"
	"github.com/majd/ipatool/v2/pkg/appstore"
	"github.com/spf13/cobra"
)

func authCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Authenticate with the App Store",
	}

	cmd.AddCommand(loginCmd())
	cmd.AddCommand(infoCmd())
	cmd.AddCommand(revokeCmd())

	return cmd
}

func loginCmd() *cobra.Command {
	var email, password, authCode, anisetteURL string

	var securityKey bool

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Login to the App Store",
		RunE: func(cmd *cobra.Command, args []string) error {
			interactive := cmd.Context().Value(interactiveKey).(bool)

			if anisetteURL != "" && !securityKey {
				return errors.New("--anisette-url requires --security-key")
			}

			if securityKey && !interactive {
				return errors.New("security-key login requires interactive mode")
			}

			if securityKey && authCode != "" {
				return errors.New("--security-key and --auth-code are mutually exclusive")
			}

			if email == "" && !interactive {
				return errors.New("an Apple ID is required when not running in interactive mode; use the \"--email\" flag")
			}

			if email == "" && interactive {
				value, err := readPrompt("enter Apple ID (email address or phone number): ", false)
				if err != nil {
					return fmt.Errorf("failed to read Apple ID: %w", err)
				}
				email = value
			}

			if password == "" && !interactive {
				return errors.New("password is required when not running in interactive mode; use the \"--password\" flag")
			}

			if password == "" && interactive {
				value, err := readPrompt("enter password: ", true)
				if err != nil {
					return fmt.Errorf("failed to read password: %w", err)
				}
				password = value
			}

			dependencies.Logger.Log().Msg("preparing authentication; the first login may take a few minutes")

			var interaction *appstore.SecurityKeyInteraction

			if securityKey {
				ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt)
				defer cancel()

				interaction = &appstore.SecurityKeyInteraction{
					AnisetteURL: anisetteURL,
					Context:     ctx,
					PIN:         readPIN,
					Status:      func(message string) { dependencies.Logger.Log().Msg(message) },
				}
			}

			var lastErr error

			// nolint:wrapcheck
			return retry.Do(func() error {
				if errors.Is(lastErr, appstore.ErrAuthCodeRequired) && interactive {
					var err error
					authCode, err = readPrompt("enter 2FA code: ", false)
					if err != nil {
						return fmt.Errorf("failed to read auth code: %w", err)
					}
				}

				dependencies.Logger.Verbose().
					Str("email", email).
					Bool("authCodeProvided", authCode != "").
					Msg("logging in")

				output, err := dependencies.AppStore.Login(appstore.LoginInput{
					SecurityKey:            securityKey,
					SecurityKeyInteraction: interaction,
					Email:                  email,
					Password:               password,
					AuthCode:               authCode,
				})
				if err != nil {
					if errors.Is(err, appstore.ErrAuthCodeRequired) && !interactive {
						dependencies.Logger.Log().Msg("2FA code is required; run the command again and supply a code using the `--auth-code` flag")

						return nil
					}

					return err
				}

				dependencies.Logger.Log().
					Str("name", output.Account.Name).
					Str("email", output.Account.Email).
					Bool("success", true).
					Send()

				return nil
			},
				retry.LastErrorOnly(true),
				retry.DelayType(retry.FixedDelay),
				retry.Delay(time.Millisecond),
				retry.Attempts(2),
				retry.RetryIf(func(err error) bool {
					lastErr = err

					return errors.Is(err, appstore.ErrAuthCodeRequired)
				}),
			)
		},
	}

	cmd.Flags().StringVarP(&email, "email", "e", "", "Apple ID email address or phone number (required)")
	cmd.Flags().StringVarP(&password, "password", "p", "", "password for the Apple ID (required)")
	cmd.Flags().StringVar(&anisetteURL, "anisette-url", "", "optional anisette-v1 service URL (HTTPS or local HTTP) for --security-key (defaults to built-in local Anisette)")
	cmd.Flags().BoolVar(&securityKey, "security-key", false, "experimental physical security-key login (macOS, USB, libfido2)")
	cmd.Flags().StringVar(&authCode, "auth-code", "", "2FA code for the Apple ID")

	return cmd
}

// nolint:wrapcheck
func infoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Show current account info",
		RunE: func(cmd *cobra.Command, args []string) error {
			output, err := dependencies.AppStore.AccountInfo()
			if err != nil {
				return err
			}

			dependencies.Logger.Log().
				Str("name", output.Account.Name).
				Str("email", output.Account.Email).
				Bool("success", true).
				Send()

			return nil
		},
	}
}

// nolint:wrapcheck
func revokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke",
		Short: "Revoke your App Store credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := dependencies.AppStore.Revoke()
			if err != nil {
				return err
			}

			dependencies.Logger.Log().Bool("success", true).Send()

			return nil
		},
	}
}
