import { DEFAULT_REQUEST_POLICY, validateRequestPolicy, parseCollectionOptions } from './requestPolicy.js';
import { EXPORT_FORMATS, type ExportFormat } from './exporter.js';
import { SEVERITIES, type Severity } from '../../shared/auditRules.js';
export function parseAuditArguments(args:string[]) {
  const command=args[0], positionals:string[]=[], options:Record<string,string|boolean>={};
  const filters:Record<string,string[]>={'--policy-filter':[],'--auth-mount-filter':[],'--auth-type-filter':[]};
  const arities:Record<string,[number,number]>={export:[2,2],collect:[0,0],scan:[0,0],analyze:[1,1],diff:[2,2],'baseline-create':[2,2],rules:[0,0],list:[0,0],configure:[1,2]};
  if(!command || !arities[command]) throw new Error('Expected export, collect, scan, analyze, diff, baseline-create, rules, list or configure');
  const analysis=['scan','analyze'].includes(command), gating=analysis||command==='diff';
  for(let i=1;i<args.length;i++) {
    const token=args[i];
    if(!token.startsWith('--')) {positionals.push(token);continue;}
    if(Object.hasOwn(filters,token)) {
      if(!['scan','collect'].includes(command)) throw new Error(`Unsupported option ${token} for ${command}`);
      const value=args[++i];if(!value||value.startsWith('--')) throw new Error(`${token} requires a value`);
      filters[token].push(value);continue;
    }
    if(Object.hasOwn(options,token)) throw new Error(`Duplicate option ${token}`);
    if(['--baseline','--exceptions'].includes(token) && analysis || token==='--fail-on' && gating || token==='--format' && command==='export' || ['--policy-filter','--auth-mount-filter','--auth-type-filter','--max-objects','--timeout-ms','--max-duration-ms','--workers','--retries','--requests-per-second','--retry-backoff-ms'].includes(token) && ['scan','collect'].includes(command)) {
      const value=args[++i]; if(!value || value.startsWith('--')) throw new Error(`${token} requires a value`);
      options[token]=value;
    } else if(token==='--skip-identity' && ['scan','collect'].includes(command)) options[token]=true;
    else if(['--save','--current-rules'].includes(token) && command==='analyze') options[token]=true;
    else if(['--require-complete','--allow-incomplete'].includes(token) && (gating||command==='collect')) options[token]=true;
    else throw new Error(`Unsupported option ${token} for ${command}`);
  }
  const [min,max]=arities[command];
  if(positionals.length<min || positionals.length>max) throw new Error(`Invalid positional arguments for ${command}`);
  if(options['--require-complete'] && options['--allow-incomplete']) throw new Error('Conflicting completeness options');
  const failOn=String(options['--fail-on']??'high');
  if(failOn!=='none' && !SEVERITIES.includes(failOn as Severity)) throw new Error('Invalid --fail-on severity');
  const format=String(options['--format']??'json');
  if(!EXPORT_FORMATS.includes(format as ExportFormat)) throw new Error('Invalid export format');
  const requestPolicy={...DEFAULT_REQUEST_POLICY};
  for(const [flag,key] of [['--retries','retries'],['--requests-per-second','requestsPerSecond'],['--retry-backoff-ms','retryBackoffMs']] as const)
    if(options[flag]!==undefined) requestPolicy[key]=Number(options[flag]);
  validateRequestPolicy(requestPolicy);
  const workers=Number(options['--workers']??10);
  if(!Number.isInteger(workers)||workers<1||workers>32) throw new Error('workers must be an integer from 1 to 32');
  return {command,positionals,save:!!options['--save'],currentRules:!!options['--current-rules'],requestPolicy:parseCollectionOptions({...requestPolicy,workers,timeoutMs:Number(options['--timeout-ms']??30000),maxDurationMs:Number(options['--max-duration-ms']??7200000),maxObjects:Number(options['--max-objects']??0),skipIdentity:!!options['--skip-identity'],policyFilters:filters['--policy-filter'],authMountFilters:filters['--auth-mount-filter'],authTypeFilters:filters['--auth-type-filter']}),format:format as ExportFormat,baseline:options['--baseline'] as string|undefined,
    exceptions:options['--exceptions'] as string|undefined,failOn:failOn as Severity|'none',
    requireComplete:!options['--allow-incomplete']};
}
export function auditExitCode(severities:Severity[], incomplete:boolean, options:{failOn:Severity|'none';requireComplete:boolean}):number {
  if(incomplete && options.requireComplete) return 2;
  if(options.failOn==='none') return 0;
  const threshold=SEVERITIES.indexOf(options.failOn);
  return severities.some(severity=>SEVERITIES.indexOf(severity)<=threshold) ? 1 : 0;
}
