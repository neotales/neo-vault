// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
	integrations: [
		starlight({
			title: 'nsvault',
			description: 'Directory-scoped secrets proxy. Values stay out of argv.',
			customCss: ['./src/styles/global.css'],
			social: [
				{
					icon: 'github',
					label: 'GitHub',
					href: 'https://github.com/neotales/neo-secrets-vault',
				},
			],
			sidebar: [
				{
					label: 'Start 🚀',
					items: [{ label: 'First config', slug: 'guides/first-config' }],
				},
				{
					label: 'How-to 🧰',
					items: [{ label: 'Agent cheat sheet', slug: 'guides/agents' }],
				},
				{
					label: 'Reference 📚',
					items: [{ autogenerate: { directory: 'reference' } }],
				},
				{
					label: 'Explanation 🧠',
					items: [{ autogenerate: { directory: 'explanation' } }],
				},
			],
		}),
	],
	vite: {
		plugins: [tailwindcss()],
	},
});
