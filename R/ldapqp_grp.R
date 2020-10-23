#' @title Checks whether a given user is member of a specific group
#' @description Function to verify whether a given user is member of a specific group
#' @name check_grp
#' @param server The ldap server to query
#' @param bind_dn Bind DN used for querying
#' @param bind_pass Bind password
#' @param base Base DN as entrypoint in the three
#' @param user User whose membership to look for
#' @param group The group to check for
#' @return Boolean 
#' @export
#' @examples
#' check_grp('ldap://myldapserver.com:389',
#'             'cn=bind_user,dc=example,dc=com',
#'             'bind_password',
#'             'cn=base,dc=example,dc=com',
#'             'user','group')

library(stringr)
library(RCurl)

check_grp <- function(ldserver,bind_dn,bind_pass,base,user,group){
  #checks if a user is member of the specified group
  cred <- paste(bind_dn,bind_pass,sep = ':')
  uri <- paste(ldserver,'/uid=',user,',',base,sep ="")
  
  result <- str_split(getURL(uri, userpwd = cred, 
                             httpauth = 1L), pattern = "\n")
  
  auth <- any(str_detect(result,regex(paste('memberOf.*',group,',',sep = ''))))
  return(auth)
}
