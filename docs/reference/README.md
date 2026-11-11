# The app-builder reference

This directory is the reference an app builder's agent reads: what the MCP tool
`api(at:"<topic>")`, `benmore api <app> <topic>` and `benmore docs <topic>` answer. It is
embedded in every edition of the binary (`reference.go`) and loaded on first use, so a
change here is a documentation change, not a Go edit.

## Layout

```
docs/reference/
  _registry.json          every topic's name ("topics"), other names that answer as a topic
                          ("aliases"), names of removed features with what replaced them
                          ("retired")
  <topic>/
    _topic.json           the topic's keys, in the order to read them; the values code builds
    <key>.txt             a text value
    <key>.json            a list, a map, or a number
```

A topic is a directory; a key is a file. `api(at:"csrf.how_to_send")` is
`docs/reference/csrf/how_to_send.txt`, `api(at:"flows.respond_headers")` is
`docs/reference/flows/respond_headers.json`, and a dotted path beyond the key
(`api(at:"flows.respond_headers.values")`) walks into a map.

- **Names.** A topic is lower case with digits, `-` and `_`. A key is lower case with digits
  and `_`: it names a file, and it is what an agent types and searches for, so use the words
  of the question it answers.
- **`<key>.txt`** holds the value followed by exactly one newline, which the loader takes
  off. Nothing else is interpreted: no escapes, no front matter.
- **`<key>.json`** holds anything that is not one text: a list of paragraphs, a map of named
  parts, a list of examples. Two-space indentation, one item per line, and `<`, `>`, `&`
  written as themselves. A whole number is a number; write a fraction as text. A list is
  delivered whole (its items have no address), so a long list of labelled paragraphs reads
  better as a map keyed by label.
- **`_topic.json`** lists every key under `"keys"`. Answers list keys sorted; the written
  order is for people reading the directory. Every topic has a `summary` key: one paragraph
  on what the topic covers, whose first sentence is the topic's line in `api(at:"index")`.

## Changing it

- Edit the key's file. To add a key, add its file and its name to `"keys"` in the topic's
  `_topic.json`; to remove one, remove both. To add a topic, add a directory with a
  `_topic.json` and a `summary.txt`, and its name to `"topics"` in `_registry.json`. Both
  lists exist so that a file or a directory that goes missing is an error, not a shorter
  reference.
- Describe what the runtime does, in the present tense, for someone who writes app source:
  no release labels, no history, no Go names, nothing only the platform operator can set.
- A value that code already knows (a table the validator checks against, a section of a
  bundled guide) is not written here. `_topic.json` lists its path under `"generated"` and
  `referenceGenerators` (`reference_generated.go`) builds it, so it cannot go stale.
- `go test -tags sqlite_fts5 -run '^(TestReference|TestDocs)' .` loads the directory the way
  the binary does and names the file that is wrong: a key with no file, a file no
  `_topic.json` lists, JSON that is not laid out as above.
- In the maintainers' repository, `python3 scripts/check-docs.py` also checks every
  `api(at:"<topic>.<key>")` address in the documentation against these files, and that the
  website's list of topics (`python3 scripts/reference_site.py` rewrites it) is current.

A topic over 8 KiB is delivered as an index of its keys, so each key should answer one
question; the maintainers' tests refuse a new key over 8 KiB.
