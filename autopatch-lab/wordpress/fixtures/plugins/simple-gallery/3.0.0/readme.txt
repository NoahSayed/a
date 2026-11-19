=== Simple Gallery ===
Stable tag: 3.0.0

== Changelog ==
= 3.0.0 =
* Security: fixed path traversal in original downloads (CVE-2026-90002).
* Breaking: the global helper sg_get_images() was removed. Use \SimpleGallery\Gallery::get_images() instead (same return value).
* Code moved into the SimpleGallery namespace.
= 2.0.0 =
* Download originals.
