const S='/tmp/claude-0/-home-user-a/085e7a47-7d23-560e-b39e-f8f23f36655f/scratchpad';
process.env.WPLAB_SCRATCH=S+'/aptest/wplab'; process.env.WP_CORE_DIR=S+'/wp/wordpress-core'; process.env.WP_SQLITE_DIR=S+'/wp/sqlite';
const {buildBase}=await import('/home/user/a/autopatch-lab/wordpress/lab/site.mjs');
console.log(buildBase());
