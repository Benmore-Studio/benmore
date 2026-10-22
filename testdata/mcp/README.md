# Fixed PDF integration fixtures

All documents contain only generated `HELLO WORLD` text. They contain no customer source or credentials. The PDF bytes are fixed test inputs; regeneration is not promised to produce the same bytes because font/rendering and PDF metadata depend on the generator.

| File | SHA-256 |
| --- | --- |
| encrypted_scan.pdf | `4a05bc59e02f85f29dff17d9788af9e79ff5aef559918a6bc2ebec9c1dff0b43` |
| scanned_hello_world.pdf | `db1b03445adb3e6155c71230bbf94af9a8817a2687f1e065fa9f948acd035f4a` |
| scanned_hello_world_rotated.pdf | `670ae1fb9503f50424268bf090544941b8211fa0f310a540cc95be1863408660` |

The normal image-only PDF was created on macOS 26.6.2 from `HELLO WORLD\n`: `cupsfilter -m application/pdf` emitted a Helvetica/Quartz native PDF; Poppler 26.10.0 `pdftoppm -f 1 -l 1 -singlefile -r 180 -png` rasterized it; `sips -s format pdf` wrapped the PNG. Integration tests run isolated `pdftotext` and require zero native text blocks before OCR.

The rotated image-only variant was produced with Ghostscript 10.00.0 `pdfwrite`, `-dAutoRotatePages=/None` and `'<</Orientation 3>> setpagedevice'`. Its landscape page contains a physically rotated raster; decoded image transforms, rendered recognition and pixel boxes are tested. It is not a native-text PDF with a rotation marker standing in for an OCR test.

The encrypted variant was produced with Ghostscript `pdfwrite`, nonempty disposable user/owner passwords and `-dPermissions=-4`. Extraction without a password must return `ErrIngestEncrypted`, no partial blocks and preserved source identity. Test passwords are not production credentials and are not needed by the rejecting parser.

The generator commands were observed during fixture creation; no generation script is retained. Ghostscript, cupsfilter and sips are fixture-generation tools only, not runtime or production dependencies.
