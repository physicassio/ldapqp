#' @title Checks whether a given user is member of a specific openldap group
#' @description Function to verify whether a given user is member of a specific openldap group
#' @name check_oldap_grp
#' @param server The ldap server to query
#' @param bind_dn Bind DN used for querying
#' @param bind_pass Bind password
#' @param base Base DN as entrypoint in the three
#' @param user User whose membership to look for
#' @param group The group to check for
#' @return Boolean
#' @export
#' @examples
#' check_oldap_grp('ldap://myldapserver.com:389',
#'             'cn=bind_user,dc=example,dc=com',
#'             'bind_password',
#'             'cn=base,dc=example,dc=com',
#'             'user','group')

library(stringr)
library(RCurl)

check_oldap_grp <- function(ldserver,bind_dn,bind_pass,base,user,group){
  #checks if a user is member of the specified openldap group
  cred <- paste(bind_dn,bind_pass,sep = ':')
  uri <- paste(ldserver,'/uid=',user,',',base,sep ="")

  result <- str_split(getURL(uri, userpwd = cred,
                             httpauth = 1L), pattern = "\n")

  auth <- any(str_detect(result,regex(paste('memberOf.*=',group,',',sep = ''))))
  return(auth)
}


#' @title Checks whether a given user is member of an AD specific group
#' @description Function to verify whether a given user is member of a specific AD group
#' @name check_AD_grp
#' @param server The AD server to query
#' @param bind_dn Bind DN used for querying
#' @param bind_pass Bind password
#' @param base Base DN as entrypoint in the three
#' @param user User whose membership to look for
#' @param group The AD group to check for
#' @return Boolean
#' @export
#' @examples
#' check_AD_grp('ldap://myldapserver.com:389',
#'             'cn=bind_user,dc=example,dc=com',
#'             'bind_password',
#'             'cn=base,dc=example,dc=com',
#'             'user','group')

check_AD_grp <- function(ldserver,bind_dn,bind_pass,base,user,group){
  #checks if a user is member of the specified AD group
  cred <- paste(bind_dn,bind_pass,sep = ':')
  uri <- paste(ldserver,'/sAMAccountName=',user,',',base,sep ="")

  result <- str_split(getURL(uri, userpwd = cred,
                             httpauth = 1L), pattern = "\n")

  auth <- any(str_detect(result,regex(paste('memberOf.*=',group,',',sep = ''))))
  return(auth)
}
