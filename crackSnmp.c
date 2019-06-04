/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   crackSnmp.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: tybbow <tybbow@gmail.com>                  +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/06/04 17:24:00 by tybbow            #+#    #+#             */
/*   Updated: 2019/06/04 17:33:44 by tybbow           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <ctype.h>
#include <openssl/md5.h>

#define OPAD 0x5c
#define IPAD 0x36
#define SIZEID 17
#define SIZEWHOLE 131
#define u_char unsigned char
#define u_long unsigned long
#define u_int unsigned int
#define GRN   "\x1B[32m"
#define RST "\x1B[0m"

typedef struct  s_snmp    t_snmp;

struct                  s_snmp
{
        u_char	opad[65];
        u_char	ipad[65];
		u_char	WHOLEMESSAGE[SIZEWHOLE];
		u_char	MSGAUTHENGINEID[SIZEID];
		u_char	K1[65];
		u_char	K2[65];
		int		read_fd;
};


int		usage()
{
	printf("Usage: crackSnmp -f Dico\n");
	return (0);
}

void passwdtomd5Key(u_char *password, u_int passwordlen, u_char *engineID, u_int engineLength, u_char *key)
{
	MD5_CTX MD;
	u_char *cp, password_buf[80], *mypass = password, bpass[17];
	u_long password_index = 0, count = 0, i, mylen, myelen = engineLength;

	if (strlen(password) > passwordlen)
    	passwordlen = strlen(password);
  	if (passwordlen > sizeof(bpass) - 1)
    	passwordlen = sizeof(bpass) - 1;
  	mylen = passwordlen;

  	if (mylen < 8) 
	{
    	memset(bpass, 0, sizeof(bpass));
    	strcpy(bpass, password);
    	while (mylen < 8) 
		{
			strcat(bpass, password);
			mylen += passwordlen;
		}
		mypass = bpass;
	}

	if (myelen > 32)
    	myelen = 32;

  	MD5_Init(&MD);
	while (count < 1048576) 
	{
		cp = password_buf;
		for (i = 0; i < 64; i++) 
			*cp++ = mypass[password_index++ % mylen];
		MD5_Update(&MD, password_buf, 64);
		count += 64;
	}
 	MD5_Final(key, &MD);
  	memcpy(password_buf, key, 16);
  	memcpy(password_buf + 16, engineID, myelen);
	memcpy(password_buf + 16 + myelen, key, 16);
	MD5(password_buf, 32 + myelen, key);
}

void	XorK1K2(t_snmp **snmp, u_char *tmp, int len)
{
	int i;

	i = 0;
	while (i < len)
	{
		(*snmp)->K1[i] = (*snmp)->ipad[i] ^ tmp[i];
		(*snmp)->K2[i] = (*snmp)->opad[i] ^ tmp[i];
		i++;
	}
}

void	decryptSnmp(t_snmp **snmp, u_char *password)
{
	u_char	tmpck1[196] = {0};
	u_char	tmpck2[80] = {0};
	u_char	key[16] = {0};
	u_char	finalHash[16] = {0};
	u_char	cmp[12] = {0xcf, 0xdc, 0x45, 0x25, 0xf8, 0x88, 0x82, 0xa4,
	0xac, 0x0a, 0x36, 0x6a};

	memcpy(tmpck1, (*snmp)->K1, 64);
	memcpy(tmpck1 + 64, (*snmp)->WHOLEMESSAGE, 131);
	MD5(tmpck1, 131 + 64, key);
	memcpy(tmpck2, (*snmp)->K2, 64);
	memcpy(tmpck2 + 64, key, 16);
	MD5(tmpck2, 80, finalHash);
	if (!memcmp(finalHash, cmp, 12))
	{
		printf(GRN "\n[+]" RST " Found Password :" GRN " %s \n" RST, password);
		exit(1);
	}
	printf(GRN "[!]" RST " Testing Password : %s\n", password);
}
void	launchSnmp(t_snmp **snmp)
{
	u_char 	**password;
	u_char	secret[64] = {0};
	u_char	buffer[4096] = {0};
	int		i;

	i = 0;
	while (read((*snmp)->read_fd, &buffer[i], 1) && i < 4096)
	{
		if (buffer[i] == '\n' || buffer[i] == 0)
		{
			buffer[i] = 0;
			passwdtomd5Key(buffer, strlen(buffer), (*snmp)->MSGAUTHENGINEID, 17, secret);
			XorK1K2(snmp, secret, 64);
			decryptSnmp(snmp, buffer);
			memset(buffer, 0, 4095);
			i = -1;
		}
		i++;
	}
}

int		initSnmp(int ac, char **av, t_snmp **snmp)
{
	int ret;

	u_char	MSGENGINEID[SIZEID] = {0x80, 0x00, 0x1f, 0x88, 0x80, 0xe9, 
	0xbd, 0x0c, 0x1d, 0x12, 0x66, 0x7a, 0x51, 0x00, 0x00, 0x00, 0x00};

	u_char	WHOLE[SIZEWHOLE] = {0x30, 0x81, 0x80, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 
	0x04, 0x20, 0xdd, 0x06, 0xa9, 0x02, 0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x05, 0x02,
	0x01, 0x03, 0x04, 0x31, 0x30, 0x2f, 0x04, 0x11, 0x80, 0x00, 0x1f, 0x88, 0x80, 0xe9,
	0xbd, 0x0c, 0x1d, 0x12, 0x66, 0x7a, 0x51, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x05,
	0x02, 0x01, 0x20, 0x04, 0x04, 0x75, 0x73, 0x65, 0x72, 0x04, 0x0c, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x30, 0x35, 0x04,
	0x11, 0x80, 0x00, 0x1f, 0x88, 0x80, 0xe9, 0xbd, 0x0c, 0x1d, 0x12, 0x66, 0x7a, 0x51,
	0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0xa0, 0x1e, 0x02, 0x04, 0x6b, 0x4c, 0x5a, 0xc4,
	0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x10, 0x30, 0x0e, 0x06, 0x0a, 0x2b, 0x06,
	0x01, 0x02, 0x01, 0x04, 0x1e, 0x01, 0x05, 0x01, 0x05, 0x00};

	memset((*snmp)->ipad, IPAD, 64);
	memset((*snmp)->opad, OPAD, 64);
	memcpy((*snmp)->MSGAUTHENGINEID, MSGENGINEID, SIZEID);
	memcpy((*snmp)->WHOLEMESSAGE, WHOLE, SIZEWHOLE);

	(*snmp)->read_fd = open(av[2], O_RDONLY);
	if ((*snmp)->read_fd == -1 || strcmp(av[1], "-f"))
		return (0);
	return (1);
}

int		main(int ac, char **av)
{
	t_snmp *snmp;

	snmp = NULL;
	snmp = malloc(sizeof(t_snmp));
	if (ac != 3 || !snmp || !initSnmp(ac, av, &snmp))
		return (usage());
	launchSnmp(&snmp);
	return (1);
}
