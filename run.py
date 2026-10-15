"""Start on localhost only. Do not expose this unauthenticated MVP publicly."""
import uvicorn
import os
from app.owner_access import issue_link, OWNER_EMAIL

if __name__ == "__main__":
    os.environ['DEVFLOW_OWNER_MODE'] = '1'
    print('DevFlow free local owner access: ' + OWNER_EMAIL)
    print('Open this one-use link within five minutes:\n' + issue_link(), flush=True)
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=False, access_log=False)
