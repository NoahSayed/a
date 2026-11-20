const S='/tmp/claude-0/-home-user-a/085e7a47-7d23-560e-b39e-f8f23f36655f/scratchpad/aptest';
process.env.WPLAB_SCRATCH=S+'/wplab';
const {grade}=await import('/home/user/a/autopatch-lab/wordpress/hidden/grade.mjs');
const r=await grade(S+'/wpsite',8301,S+'/wplab/_base-site');
console.log(r.total,r.security,r.function,r.integrity,r.supplyChain);
for(const c of r.checks) if(!c.pass) console.log('FAIL',c.name,c.detail);
