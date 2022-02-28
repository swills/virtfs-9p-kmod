virtfs-9p-kmod based on [code from Juniper](https://github.com/Juniper/virtfs/compare/jnpr/virtfs)

Build tested on 12.x, 13.x and 14.x. Run tested on 12.x.

Add these flags to bhyve: `-s 28,virtio-9p,9p=/some/local/path`

In the bhyve VM, load the module and then:

`mount -t virtfs -o trans=virtio 9p /some/vm/path`

See also:

* [9p review for bhyve](https://reviews.freebsd.org/D10335)
* [lib9p](https://github.com/conclusiveeng/lib9p)
* [9P](https://en.wikipedia.org/wiki/9P_(protocol)
* [9P protocol](http://9p.io/sys/man/5/INDEX.html)
