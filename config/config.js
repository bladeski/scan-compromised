const CONFIG = {
    advisoriesApiUrl: 'https://api.github.com/graphql',
    registryUrl: 'https://registry.npmjs.org/',
    githubToken: process.env.GITHUB_TOKEN,
    threatsFile: 'data/threats.json',
    advisoriesFile: 'data/advisories.json',
    lastUpdatedFile: 'data/lastUpdated.json',
    lastUpdatedTempFile: 'data/lastUpdatedTemp.json',
    concurrencyLimit: 10,
    progressBarLength: 30
};

export default CONFIG;