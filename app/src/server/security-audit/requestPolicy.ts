import { VaultError } from '../lib/vaultClient.js';
export interface RequestPolicyOptions { retries:number; requestsPerSecond:number; retryBackoffMs:number; }
export const DEFAULT_REQUEST_POLICY:RequestPolicyOptions={retries:3,requestsPerSecond:10,retryBackoffMs:500};
export function validateRequestPolicy(options:RequestPolicyOptions):void {
  if(!Number.isInteger(options.retries)||options.retries<0||options.retries>10) throw new Error('retries must be an integer from 0 to 10');
  if(!Number.isFinite(options.requestsPerSecond)||options.requestsPerSecond<=0||options.requestsPerSecond>1000) throw new Error('requestsPerSecond must be greater than 0 and at most 1000');
  if(!Number.isInteger(options.retryBackoffMs)||options.retryBackoffMs<0||options.retryBackoffMs>10000) throw new Error('retryBackoffMs must be an integer from 0 to 10000');
}
export function createRequestPolicy(options:RequestPolicyOptions,clock={now:()=>performance.now(),sleep:(ms:number)=>new Promise<void>(resolve=>setTimeout(resolve,ms))}) {
  validateRequestPolicy(options);
  let next=0;
  const metrics={requests:0,retries:0,rateWaitMs:0,retryWaitMs:0};
  let admission=Promise.resolve();
  function acquire():Promise<void> {
    const turn=admission.then(async()=>{
      const wait=Math.max(0,next-clock.now());
      if(wait) {metrics.rateWaitMs+=wait;await clock.sleep(wait);}
      next=clock.now()+1000/options.requestsPerSecond;
    });
    admission=turn.catch(()=>{});
    return turn;
  }
  async function request<T>(operation:()=>Promise<T>):Promise<T> {
    for(let attempt=0;;attempt++) {
      await acquire();
      metrics.requests++;
      try{return await operation();}
      catch(error) {
        const retryable=error instanceof VaultError && [408,429,500,502,503,504].includes(error.statusCode);
        if(!retryable||attempt>=options.retries) throw error;
        metrics.retries++;
        const backoff=Math.min(10000,options.retryBackoffMs*2**attempt);
        metrics.retryWaitMs+=backoff;
        if(backoff) await clock.sleep(backoff);
      }
    }
  }
  return {request,metrics};
}

export function parseCollectionOptions(raw:unknown):RequestPolicyOptions & {workers:number} {
  if(raw===undefined) return {...DEFAULT_REQUEST_POLICY,workers:10};
  if(!raw || typeof raw!=='object'||Array.isArray(raw)) throw new Error('Collection options must be an object');
  const value=raw as Record<string,unknown>;
  if(Object.keys(value).some(key=>!['workers','retries','requestsPerSecond','retryBackoffMs'].includes(key))) throw new Error('Unknown collection option');
  const options={...DEFAULT_REQUEST_POLICY,workers:10,...value} as RequestPolicyOptions & {workers:number};
  for(const value of Object.values(options)) if(typeof value!=='number') throw new Error('Collection options must be numeric');
  validateRequestPolicy(options);
  if(!Number.isInteger(options.workers)||options.workers<1||options.workers>32) throw new Error('workers must be an integer from 1 to 32');
  return options;
}
