// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Command midwatch inspects the network you are on and reports who can see or
// alter your traffic.
//
// midwatch is passive with respect to other people: it opens ordinary
// connections to public endpoints and reasons about the answers. It does not
// scan hosts it was not pointed at, and it never transmits results anywhere.
package main

import (
	"os"

	"github.com/securqbit/midwatch/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
