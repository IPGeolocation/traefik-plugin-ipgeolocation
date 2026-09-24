// Separate module on purpose: the plugin itself must stay dependency free,
// because Traefik plugin dependencies have to be vendored and Yaegi cannot
// run most of them.
module github.com/IPGeolocation/traefik-plugin-ipgeolocation/test/yaegi

go 1.21

require github.com/traefik/yaegi v0.16.1
