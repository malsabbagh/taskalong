#!/usr/bin/env python3
"""Create a disposable two-step CLI example using original synthetic test data.

Run from a matching source archive with an installed TaskAlong interpreter.
This setup writes only a new directory and performs no provider or publication
request. The fake worker is not installed as a product executor.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--review-executable', type=Path)
    args = parser.parse_args()
    root = args.directory.absolute()
    if not args.directory.is_absolute() or root.exists() or any(p.is_symlink() for p in (root, *root.parents)):
        parser.error('Choose a new absolute directory without symlink components.')
    root.mkdir(mode=0o700, parents=False)
    os.environ.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1', PYTHONDONTWRITEBYTECODE='1')
    repo = root / 'primary'; repo.mkdir(mode=0o700)
    def git(*argv):
        return subprocess.check_output(['git','-c','core.hooksPath=/dev/null','-C',str(repo),*argv],text=True).strip()
    git('init','-b','main'); git('config','user.name','Synthetic Operator')
    git('config','user.email','synthetic@example.invalid');git('config','commit.gpgsign','false')
    for name in ('a.py','b.py'):
        (repo/name).write_text('def value():\n    return 1\n')
    (repo/'check.py').write_text('from a import value\nfrom b import value as second\nassert value() == 2 and second() == 2\n')
    git('add','a.py','b.py','check.py');git('commit','-m','Generated ordered fixture baseline')
    source = Path(__file__).resolve().parents[1]
    worker=root/'synthetic-worker'
    worker.write_text((source/'tests/fixtures/fake_codex.py').read_text().replace('#!/usr/bin/env python3','#!'+sys.executable,1))
    worker.chmod(0o700)
    launcher=root/'synthetic-check-launcher'
    launcher.write_text('#!'+sys.executable+"\nimport os,sys\nargv=sys.argv[sys.argv.index('--')+1:]\nos.execv(argv[0],argv)\n")
    launcher.chmod(0o700)
    config=root/'review.yml';config.write_text('schema: 1\n')
    response=root/'review-response.json';response.write_text('{"summary":"Generated fixture review.","comments":[]}\n')
    state=root/'state'
    def cli(*argv):
        process=subprocess.run([sys.executable,'-m','taskalong','--state-dir',str(state),'--json',*map(str,argv)],capture_output=True,text=True,check=True,timeout=30)
        return json.loads(process.stdout)['data']
    registration=cli('register-repository',repo,'--workspace-root',root/'workspaces')
    # Maintenance is an explicit trusted setup action, never implicit submission.
    from taskalong.store import Store
    with Store.maintenance(state) as store:
        for number in range(2,11):
            store.upgrade(operation_key='example-format-'+str(number),backup_dir=root/('backup-'+str(number)),
                restore_dir=root/('restore-'+str(number)),target_version=number)
    from taskalong.validation import digest,seal_versioned
    profile={'profile_id':'ordered-example','qualification':'synthetic','adapter':'codex-cli',
        'executable_path':str(worker),'executable_sha256':hashlib.sha256(worker.read_bytes()).hexdigest(),
        'runtime_version':'0.163.0','model':'synthetic','reasoning_effort':'low','service_tier':None,
        'inference_destination_id':'synthetic-local-fixture','permission_policy':{},'permission_policy_digest':digest({}),
        'toolchain_read_roots':[],'credential_source_ref':None,'qualification_receipt_ids':[]}
    profile_file=root/'profile.json';profile_file.write_text(json.dumps(profile))
    profile=cli('register-profile','--profile',profile_file)
    cli('configure-sandbox','--executable',launcher)
    if args.review_executable:
        cli('configure-review','--config',config,'--fixture-response',response,'--executable',args.review_executable,'--python-executable',sys.executable)
    spec=seal_versioned('task-spec',{'extensions':{},'task_id':'ordered-example','revision':1,'goal':'Correct two generated value functions.',
        'non_goals':['No provider requests, dependencies, other files or publication.'],
        'repository':{'registration_id':registration['registration_id'],'base_commit':git('rev-parse','HEAD'),'base_ref':'main'},
        'scope':{'files':['a.py','b.py'],'operations':['modify']},
        'steps':[{'step_id':name,'goal':'Correct value in '+path,'scope':{'files':[path],'operations':['modify']},'inputs':[],'required':True} for name,path in [('A','a.py'),('B','b.py')]],
        'criteria':[{'id':'values','description':'Both functions return two.','check_ids':['values']}],
        'checks':[{'id':'values','argv':[sys.executable,'-B','check.py'],'cwd':'.','timeout_seconds':5,'expected_exit_code':0,'criterion_ids':['values'],'required':True}],
        'execution':{'adapter':'codex-cli','profile_id':profile['profile_id'],'profile_digest':profile['digest']},
        'permissions':{'local_edit':True,'local_commit':True,'inference_destination_id':'synthetic-local-fixture','allowed_effects':['execute','verify','commit_candidate']},
        'budget':{'max_attempts':4,'attempt_seconds':10,'total_active_seconds':240,'max_output_bytes':3145728,'attempt_output_bytes':65536,'hard_tokens':None,'hard_cost_usd':None},
        'final_verification':{'max_passes':2,'total_active_seconds':100,'max_output_bytes':1048576},
        'review':{'required':True,'integration':'reviewsensei','contract':'0.8.8/v1','config_digest':hashlib.sha256(config.read_bytes()).hexdigest(),'require_full_coverage':True},
        'publication':None,'qualification':'synthetic'},version='2.7')
    (root/'task.json').write_text(json.dumps(spec,indent=2)+'\n')
    print(json.dumps({'state_dir':str(state),'spec':str(root/'task.json'),'review_configured':bool(args.review_executable)}))
    return 0


if __name__=='__main__':raise SystemExit(main())
