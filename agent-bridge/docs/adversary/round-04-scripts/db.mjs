import { DatabaseSync } from "node:sqlite";
const [, , cmd, p] = process.argv;
const d = new DatabaseSync(p);
if (cmd === "make") { d.exec("CREATE TABLE cookies(k TEXT, v TEXT); INSERT INTO cookies VALUES('a','b')"); }
else console.log(JSON.stringify(d.prepare("select name from sqlite_master where type='table'").all().map((r) => r.name)), JSON.stringify(d.prepare("pragma journal_mode").get()));
d.close();
