# nvault docs site

Astro Starlight site for the CLI, provider limits, and agent-facing commands.

Tailwind 4 runs through `@tailwindcss/vite` and builds alongside Starlight. Two
decisions keep the two styling systems compatible:

- `src/styles/global.css` imports `tailwindcss/theme.css` and
  `tailwindcss/utilities.css`, not the full `tailwindcss` entry point. Tailwind's
  preflight is skipped because Starlight ships its own reset.
- Starlight loads custom CSS before its own layers. `global.css` therefore
  declares the Starlight layer order first and Tailwind's layers last, so a
  utility class beats a Starlight component style.

```sh
bun install
bun run build
```

The landing page uses emoji and two Tailwind components. The terminal panels in
`src/components/ArgvMeme.astro` are HTML and text: no third-party gif or meme is
vendored, hotlinked, or redistributed.
