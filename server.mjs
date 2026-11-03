import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse
} from '@simplewebauthn/server';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(express.json({limit:'1mb'}));
const PORT = Number(process.env.PORT || 3000);
const RP_NAME = process.env.RP_NAME || 'فاکتورینو';
const ORIGIN = process.env.ORIGIN;
const RP_ID = process.env.RP_ID;
if (!ORIGIN || !RP_ID) {
  console.error('برای امنیت، متغیرهای ORIGIN و RP_ID را در محیط هاست تنظیم کنید.');
  process.exit(1);
}
const DB_FILE = path.join(__dirname, 'webauthn-db.json');
const db = fs.existsSync(DB_FILE) ? JSON.parse(fs.readFileSync(DB_FILE,'utf8')) : {users:{}};
const challenges = new Map();
function save(){fs.writeFileSync(DB_FILE,JSON.stringify(db,null,2),{mode:0o600});}
function userRecord(id){db.users[id] ||= {credentials:[]};return db.users[id];}
function challengeKey(id,kind){return `${kind}:${id}`;}
function b64(buf){return Buffer.from(buf).toString('base64url');}
function fail(res,e){console.error(e);return res.status(400).json({error:e.message||'درخواست نامعتبر است.'});}
app.post('/api/webauthn/registration-options', async (req,res)=>{
 try{
  const {userId,username,displayName}=req.body||{};
  if(!userId || !username) return res.status(400).json({error:'اطلاعات حساب ناقص است.'});
  const u=userRecord(String(userId));
  const options=await generateRegistrationOptions({rpName:RP_NAME,rpID:RP_ID,userID:Buffer.from(String(userId)),userName:String(username),userDisplayName:String(displayName||username),attestationType:'none',authenticatorSelection:{residentKey:'preferred',userVerification:'required'},excludeCredentials:u.credentials.map(c=>({id:c.id,transports:c.transports}))});
  challenges.set(challengeKey(userId,'reg'),options.challenge);
  res.json(options);
 }catch(e){fail(res,e)}
});
app.post('/api/webauthn/registration-verify', async (req,res)=>{
 try{
  const {userId,response}=req.body||{};const expectedChallenge=challenges.get(challengeKey(userId,'reg'));
  if(!expectedChallenge)return res.status(400).json({error:'درخواست ثبت منقضی شده است؛ دوباره تلاش کن.'});
  const verification=await verifyRegistrationResponse({response,expectedChallenge,expectedOrigin:ORIGIN,expectedRPID:RP_ID,requireUserVerification:true});
  challenges.delete(challengeKey(userId,'reg'));
  if(verification.verified&&verification.registrationInfo){
   const info=verification.registrationInfo;const credential=info.credential||{id:b64(info.credentialID),publicKey:info.credentialPublicKey,counter:info.counter,transports:response.response?.transports||[]};
   const u=userRecord(String(userId));u.credentials=u.credentials.filter(c=>c.id!==credential.id);u.credentials.push({id:credential.id,publicKey:b64(credential.publicKey),counter:credential.counter,transports:credential.transports||[]});save();
  }
  res.json({verified:verification.verified});
 }catch(e){fail(res,e)}
});
app.post('/api/webauthn/authentication-options', async (req,res)=>{
 try{
  const {userId}=req.body||{};if(!userId)return res.status(400).json({error:'شناسه حساب لازم است.'});
  const u=db.users[String(userId)];if(!u?.credentials?.length)return res.status(404).json({error:'برای این حساب Passkey ثبت نشده است.'});
  const options=await generateAuthenticationOptions({rpID:RP_ID,allowCredentials:u.credentials.map(c=>({id:c.id,transports:c.transports})),userVerification:'required'});
  challenges.set(challengeKey(userId,'auth'),options.challenge);res.json(options);
 }catch(e){fail(res,e)}
});
app.post('/api/webauthn/authentication-verify', async (req,res)=>{
 try{
  const {userId,response}=req.body||{};const expectedChallenge=challenges.get(challengeKey(userId,'auth'));const u=db.users[String(userId)];
  if(!expectedChallenge||!u)return res.status(400).json({error:'درخواست ورود منقضی شده یا حساب پیدا نشد.'});
  const stored=u.credentials.find(c=>c.id===response.id);if(!stored)return res.status(400).json({error:'این Passkey برای حساب ثبت نشده است.'});
  const verification=await verifyAuthenticationResponse({response,expectedChallenge,expectedOrigin:ORIGIN,expectedRPID:RP_ID,requireUserVerification:true,credential:{id:stored.id,publicKey:Buffer.from(stored.publicKey,'base64url'),counter:stored.counter,transports:stored.transports}});
  challenges.delete(challengeKey(userId,'auth'));
  if(verification.verified){stored.counter=verification.authenticationInfo.newCounter;save();}
  res.json({verified:verification.verified});
 }catch(e){fail(res,e)}
});
app.post('/api/webauthn/remove',(req,res)=>{const {userId}=req.body||{};if(!userId)return res.status(400).json({error:'شناسه حساب لازم است.'});if(db.users[String(userId)]){db.users[String(userId)].credentials=[];save();}res.json({ok:true});});
app.use(express.static(__dirname,{index:'index.html'}));
app.listen(PORT,()=>console.log(`Faktorino listening on ${PORT}`));
