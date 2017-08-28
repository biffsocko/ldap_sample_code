/*********************************************************************************************
 * BiffSocko                                                                                 *
 * ldaptest.c                                                                                *
 *                                                                                           *
 * uses openLdap libraries to connect to ActiveDirectory and returns the attributes of a     *
 * userid                                                                                    *
 *                                                                                           *
 * COMPILE: gcc -o ldaptest ldaptest.c -lldap                                                *
 *********************************************************************************************/
#include <stdio.h>
#include <ldap.h>
#include <lber.h>
#include <stdlib.h>

#define HOSTNAME "ad.mlp.com"
#define MAX 1024
#define PORTNUMBER 389
#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0

int main(int argc, char *argv[])
{
      LDAP  *ld;                                             /* ldap */
      char  *dn;                                             /* pointer to hold dn info from AD */
      char *attr;                                            /* pointer for attributes */
      int   version, rc;                                     /* version and stuff */
      char  *base = "OU=AD_Users,DC=AD,DC=foo,DC=com";       /* base from where to start search */
      /*char *filter = "(objectclass=*)";*/                  /* returns everything */
      char filter[MAX];                                      /* ldap search filter */
      char *errstring;                                       /* pointer to errors str from oldap api*/
      char **vals;                                           /* values of each attribute */
      int i;                                                 /* counter */
      int result;                                            /* result */
      BerElement *ber;                                       /* struct for ad encoding rules */
      LDAPMessage *msg;                                      /* message */
      LDAPMessage *entry;                                    /* ldap entry struct */

      
      /*******************************/
      /* check usage                 */
      /*******************************/
      if( argc != 2 ){
           printf("useage: %s [username]\n", argv[0]);
           exit( EXIT_FAILURE);
      }

      if((sprintf(filter,"uid=%s",argv[1])) < 0){
           perror("error in sprintf\n");
	   exit(EXIT_FAILURE);
      }

      /*******************************/
      /* ldap connection credentials */
      /*******************************/
      const char *root_dn = "CN=ServiceLDAP,OU=Directory,OU=Service_Accounts,OU=IT,OU=AD_Users,DC=AD,DC=MLP,DC=com";
      char *root_pass = "yourpassword";


      /*******************************/
      /* initialize ldap connection  */
      /*******************************/
      printf("Connecting %s in port %d...\n\n", HOSTNAME, PORTNUMBER);
      if((ld = ldap_init(HOSTNAME, PORTNUMBER)) == NULL){
              printf("rc ldap_initialize Error ! - ");
      }

      /*******************************/
      /* set ldap version            */
      /*******************************/
      version = LDAP_VERSION3;
      ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);


      /*******************************/
      /* bind to the ldap            */
      /*******************************/
      rc = ldap_simple_bind_s(ld, root_dn, root_pass, LDAP_AUTH_SIMPLE );
      if (rc != LDAP_SUCCESS) {
              fprintf(stderr, "Error: %s\n", ldap_err2string(rc));
              return (1);
      }

      /*******************************/
      /* search ldap                 */
      /*******************************/
      if(ldap_search_s(ld,base,LDAP_SCOPE_SUBTREE,filter,NULL,0,&msg) != LDAP_SUCCESS){
            ldap_perror(ld,"ldap_search_s");
            exit(EXIT_FAILURE);
      }

      /*******************************/
      /* get the first entry         */
      /*******************************/
      if((entry = ldap_first_entry(ld,msg)) != NULL){

            /*******************************/
            /* print the dn                */
            /*******************************/
            if((dn = ldap_get_dn(ld,entry)) != NULL){
		printf("Returned dn = %s\n",dn);
		ldap_memfree(dn);
            }
     
            /*******************************/
            /* for each attribute of entry */
            /* print the value             */
            /*******************************/
            for(attr = ldap_first_attribute(ld,entry,&ber); attr != NULL; attr = ldap_next_attribute(ld,entry,ber)){
   
  
                /*******************************/
                /* ditch fields that mess up   */
                /* my terminal .. ms bitchez   */
                /*******************************/
                if((strcasecmp(attr,"msExchMailboxSecurityDescriptor")) == 0){
		    continue;
                }
    
                if((strcasecmp(attr,"userParameters")) == 0){
                    continue;
                }

		if((strcasecmp(attr,"msExchMailboxGuid")) == 0){
                    continue;
                }

 		if((strcasecmp(attr,"objectGUID")) == 0){
                    continue;
                }

 		if((strcasecmp(attr,"objectSid")) == 0){
                    continue;
                }


 		if((strcasecmp(attr,"userCertificate")) == 0){
                    continue;
                }

		/*printf("attr = %s\n",attr);*/
                if((vals = ldap_get_values(ld,entry,attr))!= NULL){
                      for(i=0; vals[i] != NULL; i++){
                             printf("%s: %s\n",attr, vals[i]);
                      }
                      ldap_value_free(vals);
                }
                ldap_memfree(attr);
             }

             if(ber != NULL){
                 ber_free(ber,0);
             }
 
             printf("\n");
      }

      ldap_msgfree(msg);
      /*******************************/
      /* unbind from ldap            */
      /*******************************/
      result = ldap_unbind_s(ld);
      if(result != 0){
           perror("ldap unbind error");
           exit(EXIT_FAILURE);
      }

      return(EXIT_SUCCESS);
}

