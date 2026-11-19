# Article 1: one quality figure is not enough

A short post about commands hidden in tool descriptions and how far an automatic
check can be relied on: 93.8% of attacks flagged on one corpus, 32.6% on another.

| File | Purpose |
|---|---|
| `post.ru.md` | Russian text, for Max |
| `post.en.md` | English text, for LinkedIn |
| `first-comment.md` | Text for the first comment, which carries the link |
| `slides/slide-ru-*.png`, `slides/slide-en-*.png` | Four square 1200×1200 slides per language |
| `slides/slides-ru.pdf`, `slides/slides-en.pdf` | The same slides as one document, for a LinkedIn document post |

The text is written for a reader who does not know what MCP is: it explains
the threat first, then what an automatic check can and cannot find, and ends on
what follows for anyone who connects tools to an assistant.

Every figure in the text and on the slides comes from
[benchmark/README.md](../../benchmark/README.md). The other scanner measured
there is not named in the post, because the post has no room for the
qualifications that comparison needs.
