// Package jcaprovider embeds the Java JCA provider source so the ekm SDK
// download ships exactly what is in this directory, nothing written
// elsewhere.
package jcaprovider

import "embed"

//go:embed README.md pom.xml samples src/main
var Source embed.FS
