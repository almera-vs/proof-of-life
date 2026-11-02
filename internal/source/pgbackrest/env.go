package pgbackrest

import "os"

func lookupAWS() (key, secret, token string) {
	return os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"), os.Getenv("AWS_SESSION_TOKEN")
}
