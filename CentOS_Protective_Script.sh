#!/bin/bash
##Filename:     OS-centOS-Protective_v0.1.sh
##Author:	Browser
##Date:         2019-02-24
##Description:  Operating system security reinforcement


#########################variables############################
restart_flag=1
ostype='unknow'
###########################ostype############################
if [ -f /etc/redhat-release ];then
    grep -i 'centos' /etc/redhat-release > /dev/null
    if [ $? == 0 ];then
        ostype='centos'
    fi
    grep -i 'redhat' /etc/redhat-release > /dev/null
    if [ $? == 0 ];then
        ostype='redhat'
    fi
fi

if [ -f /etc/centos-release ];then
    grep -i 'centos' /etc/centos-release > /dev/null
    if [ $? == 0 ];then
        ostype='centos'
    fi
fi

if [ -f /etc/lsb-release ];then
    grep -i 'ubuntu' /etc/lsb-release > /dev/null
    if [ $? == 0 ];then
        ostype='ubuntu'
    fi
fi

if [ -f /System/Library/CoreServices/SystemVersion.plist ];then
    ostype='macOS'
fi
    echo -e "###########################################################################################"
    echo -e "\033[1;31m	    OS type is $ostype	    \033[0m"
    echo -e "###########################################################################################"

#######################restart_ssh################################
function restart_ssh(){
    if [ $restart_flag == 0 ];then
        echo -e "\033[1;31mPlease restart SSH service manully by using 'service sshd restart' or 'systemctl restart sshd'\033[0m"
    fi
}

###########################文件备份############################
function backup(){
if [ ! -x "backup" ]; then
    mkdir backup
    if [ -f /etc/pam.d/system-auth ];then
        cp /etc/pam.d/system-auth backup/system-auth.bak
    elif [ -f /etc/pam.d/common-password ];then
        cp /etc/pam.d/common-password backup/common-password.bak
    fi
    if [ -f ~/.ssh/authorized_keys ];then
        cp ~/.ssh/authorized_keys backup/authorized_keys.bak
    fi
    cp /etc/pam.d/sshd backup/sshd.bak
    cp /etc/sudoers backup/sudoers.bak
    cp /etc/ssh/sshd_config backup/sshd_config.bak
    cp /etc/profile backup/profile.bak
    cp /etc/pam.d/su backup/su.bak
    cp /etc/login.defs backup/login_defs.bak  # 增加备份/etc/login.defs
    cp /etc/logrotate.conf backup/logrotate_conf.bak  # 增加备份/etc/logrotate.conf
    echo -e "###########################################################################################"
    echo -e "\033[1;31m	    Auto backup successfully	    \033[0m"
    echo -e "###########################################################################################"
else
    echo -e "###########################################################################################"
    echo -e "\033[1;31mBackup file already exist, to avoid overwriting these files, backup will not perform again\033[0m "
    echo -e "###########################################################################################"
fi
}
###########################执行备份############################
backup

###########################文件还原############################
function recover(){
if [ -f backup/system-auth.bak ];then
    cp -rf backup/system-auth.bak /etc/pam.d/system-auth
elif [ -f backup/common-password.bak ];then
    cp -rf backup/common-password.bak /etc/pam.d/common-password
fi
if [ -f backup/authorized_keys.bak ];then
    cp -rf backup/authorized_keys.bak ~/.ssh/authorized_keys
fi
    cp -rf backup/sshd.bak /etc/pam.d/sshd
    cp -rf backup/sudoers.bak /etc/sudoers
    cp -rf backup/sshd_config.bak /etc/ssh/sshd_config
    cp -rf backup/profile.bak /etc/profile
    cp -rf backup/login_defs.bak /etc/login.defs  # 增加还原login.defs
    cp -rf backup/logrotate_conf.bak /etc/logrotate.conf  # 增加还原logrotate.conf
    source /etc/profile
    cp -rf backup/su.bak /etc/pam.d/su
    restart_flag=0
    echo -e "\033[1;31m	   8、 Recover success	\033[0m"
}

###########################口令复杂度设置############################
function password(){
    echo "#########################################################################################"
    echo -e "\033[1;31m	   2、 set password complexity requirements	\033[0m"
    echo "#########################################################################################"

if [ -f /etc/pam.d/system-auth ];then
    config="/etc/pam.d/system-auth"
elif [ -f /etc/pam.d/common-password ];then
    config="/etc/pam.d/common-password"
else
    echo -e "\033[1;31m	    Doesn't support this OS	    \033[0m"
    return 1
fi

    grep -i "^password.*requisite.*pam_cracklib.so" $config  > /dev/null
    if [ $? == 0 ];then
        sed -i "s/^password.*requisite.*pam_cracklib\.so.*$/password    requisite       pam_cracklib.so retry=3 difok=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/g" $config
	echo -e "\033[1;31m密码修改重试3次机会，新密码与老密码必须有3字符不同，最小密码长度12个字符，包含大写字符至少一个，小写字母至少一个，数字至少一个，特殊字符至少一个\033[0m"
    else
        grep -i "pam_pwquality\.so" $config > /dev/null
        if [ $? == 0 ];then
            sed -i "s/password.*requisite.*pam_pwquality\.so.*$/password     requisite       pam_pwquality.so retry=3 difok=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/g" $config
	    echo -e "\033[1;31m密码修改重试3次机会，新密码与老密码必须有3字符不同，最小密码长度12个字符，包含大写字符至少一个，小写字母至少一个，数字至少一个，特殊字符至少一个\033[0m"
        else
            echo 'password      requisite       pam_cracklib.so retry=3 difok=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1' >> $config
	    echo -e "\033[1;31m密码修改重试3次机会，新密码与老密码必须有3字符不同，最小密码长度12个字符，包含大写字符至少一个，小写字母至少一个，数字至少一个，特殊字符至少一个\033[0m"
        fi
    fi

    if [ $? == 0 ];then
        echo -e "\033[37;5m	    [Password complexity set success]	\033[0m"
    else
        echo -e "\033[31;5m	    [Password complexity set failed]	\033[0m"
	exit 1
    fi
}

################################新增超级管理员用户################################
function create_user(){
    echo "#########################################################################################"
    echo -e "\033[1;31m	   3、Create openroot account	\033[0m"
    echo "#########################################################################################"
    read -p "Be sure to create an openroot account?[y/n]:"
    case $REPLY in 
    y)
	grep -i 'openroot' /etc/passwd
        if [ $? == 0 ];then
	    echo -e "\033[1;31m		An openroot account has been created	\033[0m"
        else
	    read -p "Please enter your password:" PASSWD
	    useradd -g root openroot;echo "$PASSWD" | passwd --stdin openroot  > /dev/null
	    if [ $? == 0 ];then
		echo -e "\033[1;31m	openroot account created successfully	    \033[0m"
		grep -i "openroot" /etc/sudoers
		if [ $? != 0 ];then
		    chmod u+w /etc/sudoers > /dev/null 
		    sed -i '/^root.*ALL=(ALL).*$/a\openroot  ALL=(ALL)       NOPASSWD:ALL' /etc/sudoers > /dev/null
		    if [ $? == 0 ];then
			echo -e "\033[37;5m	    [Permissions set success]	\033[0m"
		    else
			echo -e "\033[31;5m	    [Permissions set failed]	\033[0m"
		    fi
		    chmod u-w /etc/sudoers > /dev/null 
		else
		    echo -e "\033[1;31m	    Permissions have already been set	    \033[0m"
		fi
	    else
		echo -e "\033[1;31m	    openroot account created failed	    \033[0m"
		exit 1 
	    fi
	fi
	;;
    n)
	;;
    *)
	create_user
    esac
}
############################限制超级管理员用户远程登录############################
function remote_login(){
    echo "#########################################################################################"
    echo -e "\033[1;31m	   4、Set Remote Login Configuration(SSH)	\033[0m"
    echo "#########################################################################################"
#set Protocol 2
    echo >> /etc/ssh/sshd_config
    grep -i '^Protocol' /etc/ssh/sshd_config > /dev/null
    if [ $? == 0 ];then
        sed -i 's/^Protocol.*$/Protocol 2/g' /etc/ssh/sshd_config
        if [ $? != 0 ];then
            echo -e "\033[31;5m	    [##Error##]: Cannot to set Protocol to '2'	    \033[0m"
        else
            echo -e "\033[37;5m	    [Success: Set SSH Protocol to 2]	    \033[0m"
         fi
    else
        echo 'Protocol 2' >> /etc/ssh/sshd_config
        echo -e "\033[37;5m	    [Success: Set SSH Protocol to 2]	    \033[0m"
    fi
    
    read -p "Disable root remote login?[y/n](Please make sure you have created at least one another account):"
    case $REPLY in
    y)
	grep -i '^PermitRootLogin no' /etc/ssh/sshd_config > /dev/null
	if [ $? == 1 ];then
            grep -i '.*PermitRootLogin yes' /etc/ssh/sshd_config >/dev/null
            if [ $? == 0 ];then
                sed -i 's/.*PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
                if [ $? != 0 ];then
                    echo -e "\033[31;5m	[##Error##]cannot to set PermitRootLogin to 'no'	\033[0m"
                else
        	    echo -e "\033[37;5m	    Disable root remote login[Success]	    \033[0m"
        	    restart_flag=0
                fi
            else
                echo 'PermitRootLogin no' >> /etc/ssh/sshd_config
        	echo -e "\033[37;5m	    Disable root remote login[Success]	    \033[0m"
                restart_flag=0
            fi
	else
	    echo -e "\033[37;5m	    Already disable root remote login	\033[0m"
	fi
	;;
    n)
        ;;
    *)
        remote_login
	;;
    esac
}

#######################配置系统历史命令操作记录和定时帐户自动登出时间################################
function set_history_tmout(){
    echo "#########################################################################################"
    echo -e "\033[1;31m	    5、set history and timeout	\033[0m"
    echo "#########################################################################################"
    read -p "set history size, format, and TMOUT?[y/n]:"
    case $REPLY in
    y)
	#history_size
        grep -i "^HISTSIZE=" /etc/profile >/dev/null
        if [ $? == 0 ];then
	#history记录保留一万条
            sed -i "s/^HISTSIZE=.*$/HISTSIZE=10000/g" /etc/profile
        else
            echo 'HISTSIZE=10000' >> /etc/profile
        fi
        echo -e "\033[1;31m	    HISTSIZE has been set to 10000	    \033[0m"
	#history_format
        grep -i "^export HISTTIMEFORMAT=" /etc/profile > /dev/null
        if [ $? == 0 ];then
            sed -i 's/^export HISTTIMEFORMAT=.*$/export HISTTIMEFORMAT="%F %T `whoami`"/g' /etc/profile
        else
            echo 'export HISTTIMEFORMAT="%F %T `whoami` "' >> /etc/profile
        fi
        echo -e '\033[1;31m	    HISTTIMEFORMAT has been set to "Number-Time-User-Command"	    \033[0m'
	#TIME_OUT
        read -p "set shell TMOUT?[300-600]seconds:" tmout 
	: ${tmout:=600}
        grep -i "^TMOUT=" /etc/profile	> /dev/null
        if [ $? == 0 ];then
            sed -i "s/^TMOUT=.*$/TMOUT=$tmout/g" /etc/profile
        else
            echo "TMOUT=$tmout" >> /etc/profile
        fi
        source /etc/profile
	echo -e "\033[37;5m	    [Success]	    \033[0m"
        ;;
    n)
        ;;
    *)
        set_history_tmout;;
    esac
}


#######################SSH端口配置################################
function ssh_port(){
    echo "#########################################################################################"
    echo -e "\033[1;31m	    6、set ssh port	\033[0m"
    echo "#########################################################################################"
    read -p 'change ssh port?[y/n]:'
    case $REPLY in
    y)
        read -p 'please input the new ssh port(recommend to between 1024 and 65534, please make sure the port is not in used):' port
	##验证端口是否被占用
	if [[ $port -gt 1024 && $port -lt 65535 ]];then
          netstat -tlnp|awk -v port=$port '{lens=split($4,a,":");if(a[lens]==port){exit 2}}'  >/dev/null #2>&1
          res=$?
	    if [ $res == 2 ];then
              echo -e "\033[1;31m	    The port $port is already in used, try again	\033[0m"
              ssh_port
	    elif [ $res == 1 ];then
		echo -e "\033[31;5m	    [##Error##]	    \033[0m"
		exit 1
	    else
		##修改ssh端口
		grep -i "^#Port " /etc/ssh/sshd_config > /dev/null
		if [ $? == 0 ];then
		    sed -i "s/^#Port.*$/Port $port/g" /etc/ssh/sshd_config
		else
		    grep -i "^Port " /etc/ssh/sshd_config > /dev/null
		    if [ $? == 0 ];then
			sed -i "s/^Port.*$/Port $port/g" /etc/ssh/sshd_config
		    else
			echo "Port $port" >> /etc/ssh/sshd_config
		    fi
		fi
		echo -e "\033[37;5m	    [Success]	    \033[0m"
		restart_flag=0
	    fi
	else
            echo -e "\033[31;5m	    [##The port $port is error, please input new ssh port between 1024 and 65534 ##]	    \033[0m"
	    ssh_port
        fi
        ;;
    n)
        ;;
    *)
        echo -e "\033[31;5m	    [##Error##]:invalid input	    \033[0m"
        ssh_port
	;;
    esac
}

#######################Logon failure handling################################
function logon(){
    echo "#########################################################################################"
    echo -e "\033[1;31m	    7、set logon failure handling		\033[0m"
    echo "#########################################################################################"
logonconfig=/etc/pam.d/sshd
    read -p 'Are you sure set logon failure handling?[y/n]:'
    case $REPLY in
    y)
	grep -i "^auth.*required.*pam_tally2.so.*$" $logonconfig  > /dev/null
	if [ $? == 0 ];then
	   sed -i "s/auth.*required.*pam_tally2.so.*$/auth required pam_tally2.so deny=3 unlock_time=300 even_deny_root root_unlock_time=300/g" $logonconfig > /dev/null
        else
	   sed -i '/^#%PAM-1.0/a\auth required pam_tally2.so deny=3 unlock_time=300 even_deny_root root_unlock_time=300' $logonconfig > /dev/null
        fi
    
	if [ $? == 0 ];then
	    echo "#########################################################################################"
	    echo -e "\033[37;5m	    [Logon failure handling set success]	\033[0m"
	    echo -e "\033[1;31m限制登入失败三次，普通账号锁定5分钟，root账号锁定5分钟\033[0m"
	    echo "#########################################################################################"
	else
	    echo "#########################################################################################"
	    echo -e "\033[31;5m	    [Logon failure handling set failed]	\033[0m"
	    echo "#########################################################################################"
	    exit 1
	fi
	;;
    n)
	;;
    *)
	echo -e "\033[31;5m         [##Error##]:invalid input       \033[0m"
	logon
	;;
    esac
}

#######################修改系统/etc/login.defs文件中的记录成功登录的信息，允许记录未知用户名登录失败的信息################################
#######################修改系统/etc/login.defs文件中的设置密码长度和定期更换要求参数################################
function modify_login_defs() {
    #Set logging of successful logins to yes
    LOG_OK_LOGINS="yes"

    #Set logging of unknown usernames when login failures are recorded to yes
    LOG_UNKFAIL_ENAB="yes"

    #Set maximum days between password changes to 90
    PASS_MAX_DAYS="90"

    #Set minimum days before users can change their password to 0
    PASS_MIN_DAYS="0"

    #Set the minimum password length to 8
    PASS_MIN_LEN="8"

    #Set the warning age for password expiration to 7
    PASS_WARN_AGE="7"

    # Read the /etc/login.defs file
    while read line
    do
        #skip comment lines
        if [[ "$line" =~ ^#.* ]]; then
            continue
        fi

        # Check if the line contains LOG_OK_LOGINS
        if [[ $line == *LOG_OK_LOGINS* ]]
        then
            # Replace the line with the new LOG_OK_LOGINS value
            sed -i "s/$line/LOG_OK_LOGINS\t\t$LOG_OK_LOGINS/g" /etc/login.defs
        fi

        # Check if the line contains LOG_UNKFAIL_ENAB
        if [[ $line == *LOG_UNKFAIL_ENAB* ]]
        then
            # Replace the line with the new LOG_UNKFAIL_ENAB value
            sed -i "s/$line/LOG_UNKFAIL_ENAB\t$LOG_UNKFAIL_ENAB/g" /etc/login.defs
        fi

        # Check if the line contains PASS_MAX_DAYS
        if [[ $line == *PASS_MAX_DAYS* ]]
        then
            # Replace the line with the new PASS_MAX_DAYS value
            sed -i "s/$line/PASS_MAX_DAYS\t$PASS_MAX_DAYS/g" /etc/login.defs
        fi

        # Check if the line contains PASS_MIN_DAYS
        if [[ $line == *PASS_MIN_DAYS* ]]
        then
            # Replace the line with the new PASS_MIN_DAYS value
            sed -i "s/$line/PASS_MIN_DAYS\t$PASS_MIN_DAYS/g" /etc/login.defs
        fi

        # Check if the line contains PASS_MIN_LEN
        if [[ $line == *PASS_MIN_LEN* ]]
        then
            # Check if the PASS_MIN_LEN is blank
            if [[ -z $line ]]
            then
                # Append the PASS_MIN_LEN to the end of the /etc/login.defs file
                echo "PASS_MIN_LEN $PASS_MIN_LEN" >> /etc/login.defs
            else
                # Replace the line with the new PASS_MIN_LEN value
                sed -i "s/$line/PASS_MIN_LEN\t$PASS_MIN_LEN/g" /etc/login.defs
            fi
        fi

        # Check if the line contains PASS_WARN_AGE
        if [[ $line == *PASS_WARN_AGE* ]]
        then
            # Replace the line with the new PASS_WARN_AGE value
            sed -i "s/$line/PASS_WARN_AGE\t$PASS_WARN_AGE/g" /etc/login.defs
        fi
    done < /etc/login.defs
}

#######################修改系统/etc/logrotate.conf文件中的rotate值################################
function modify_logrotate_conf()
{
	conf_file="/etc/logrotate.conf"
	sed -i '/^[^#]*weekly/,/rotate/{s/rotate.*/rotate 26/}' /etc/logrotate.conf	#week中rotate的值替换为26
	sed -i '/^[^#]*\/var\/log\/wtmp/,/rotate/{s/rotate.*/rotate 7/}' /etc/logrotate.conf	#将/var/log/wtmp下monthly中rotate的值替换为7
	sed -i '/^[^#]*\/var\/log\/btmp/,/rotate/{s/rotate.*/rotate 7/}' /etc/logrotate.conf	#将/var/log/btmp下monthly中rotate的值替换为7
}


#######################main################################
function main(){
    echo  -e "\033[1;31m
#################################################################################################################
#                                        Menu									#
#         1:ALL protective (一键进行全部加固、如有不需要执行全部加固的，请自行更改函数调用)			#
#         2:Set Password Complexity Requirements (设置密码复杂度)						#
#         3:Create openroot account (添加openroot账号)								#
#         4:Set Remote Login Configuration(SSH) (禁止root远程登入)						#
#         5:Set Shell History and TMOUT (设置history保存行数以及命令时间，设置窗口超时时间)			#
#         6:Set SSH Port (更改SSH端口)										#
#         7:Set Logon failure handling (登入失败处理)								#
#         8:Recover Configuration (还原配置文件)								#
#	  9:Modify loginDefs (设置密码长度和定期更换要求)							#
#	  10:Modify logrotateConf (建议操作系统对审计记录进行保护，通过日志服务器对审计记录进行定期存档备份)	#
#	  11:Exit (退出)                                                                         		#
################################################################################################################# \033[0m"
    read -p "Please choice[1-11]:"
    case $REPLY in
    1)
        password
        set_history_tmout
	logon
        modify_login_defs
	modify_logrotate_conf
        restart_ssh
        ;;
    2)
        password
	;;
    3)
        create_user
	;;
    4)
        remote_login
        restart_ssh
	;;
    5)
        set_history_tmout
	;;
    6)
        ssh_port
        restart_ssh
	;;
    7)
	logon
        restart_ssh
	;;
    8)
        recover
        restart_ssh
	;;
    9)
        modify_login_defs
        restart_ssh
	;;
    10)
        modify_logrotate_conf
        restart_ssh
	;;
    11)
        exit 0
	;;
    *)
        echo -e "\033[31;5m	invalid input	    \033[0m"
        main
	;;
    esac
}

######################
main
