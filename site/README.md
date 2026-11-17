# nsvault docs site

Astro Starlight site for the CLI, provider limits, and agent-facing commands.

Tailwind was not added. `create-astro --add tailwind` did not install it, and
Starlight's theme already builds. A second styling system was left out rather
than risk a broken build.

```sh
bun install
bun run build
```

No third-party meme or gif is vendored. The landing page uses emoji only.
