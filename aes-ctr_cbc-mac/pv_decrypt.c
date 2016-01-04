#include "pv.h"

long int makedivis(long int num, long int divisby)
{
  long int rmdr;
  if (divisby == 0)
    return num;
  rmdr = num%divisby;
  if (rmdr == 0)
    return num;
  else
    return num+divisby-rmdr;
}

void decrypt_file (const char *ptxt_fname, void *raw_sk, size_t raw_len, int fin)
{
  int ptxtfd;
  int numread;
  int n;
  long int finsize;
  long int remain;
  long int totalread;
  int i;
  char *outputbuf;
  char *outputbak;
  char *ptxtbuf;
  char *ctxtbuf;
  char *macbuf;
  char *actmac;
  char *ctrkey;
  char *mackey;
  char *nonce;
  char macchk;
  aes_ctx aesctr;
  aes_ctx aescbcmac;
  ptxtbuf   = (char *)malloc(BLKSIZE*sizeof(char));
  ctxtbuf   = (char *)malloc(BLKSIZE*sizeof(char));
  actmac    = (char *)malloc(BLKSIZE*sizeof(char));
  ctrkey    = (char *)malloc(CCA_STRENGTH*sizeof(char));
  mackey    = (char *)malloc(CCA_STRENGTH*sizeof(char));
  nonce     = (char *)malloc(BLKSIZE*sizeof(char));
  /* calculate and store fin filesize */
  finsize = lseek(fin,0,SEEK_END)- lseek(fin,0,SEEK_SET);
  remain  = finsize - (2*BLKSIZE);
  /* malloc outputbuf size equal to filesize */
  outputbuf = (char *)malloc(finsize*sizeof(char));
  memset(outputbuf,0,finsize*sizeof(char));
  lseek(fin,0,SEEK_SET);
  /* back up outputbuf starting ptr */
  outputbak = outputbuf;
  /* set CBC-MAC IV */
  macbuf = (char *)numtobuf(finsize-(2*BLKSIZE));
  macchk    = 1;
  totalread = 0;
  /* open plaintext file for writing */
  if ( (ptxtfd = open(ptxt_fname,O_WRONLY|O_TRUNC|O_CREAT,0600)) == -1 )
    {
      perror(getprogname());
      memset(raw_sk,0,raw_len*sizeof(char));
      free(raw_sk);
      raw_sk = NULL;
      exit(-1);
    }
  /* First, read the IV (Initialization Vector) */
  if ( (numread = read(fin,nonce,BLKSIZE)) < BLKSIZE )
    {
      puts("Failed to read IV from file\n");
      memset(raw_sk,0,raw_len*sizeof(char));
      free(raw_sk);
      raw_sk = NULL;
      exit(-1);
    }
  /* seek to AES-CBC-MAC portion of ctxt file */
  lseek(fin,-16,SEEK_END);
  /* read in AES-CBC-MAC */
  if ( (numread = read(fin,actmac,BLKSIZE)) < BLKSIZE )
    {
      puts("Failed to read MAC from file\n");
      memset(raw_sk,0,raw_len*sizeof(char));
      free(raw_sk);
      raw_sk = NULL;
      exit(-1);
    }
  /* set pos back to beginning of actual ctxt (right after IV) */
  lseek(fin,16,SEEK_SET);
  /* The buffer for the symmetric key actually holds two keys: */
  /* use the first key for the AES-CTR encryption ...*/
  memcpy(ctrkey,raw_sk,CCA_STRENGTH*sizeof(char));
  aes_setkey(&aesctr,ctrkey,CCA_STRENGTH);
  /* ... and the second part for the AES-CBC-MAC */
  memcpy(mackey,raw_sk+CCA_STRENGTH,CCA_STRENGTH*sizeof(char));
  aes_setkey(&aescbcmac,mackey,CCA_STRENGTH);
  /* start reading actual ciphertext */
  if ( remain < 16)
    numread = read(fin,ctxtbuf,remain);
  else
    numread = read(fin,ctxtbuf,BLKSIZE);
  remain -= numread;
  totalread = numread;
  /* while there is at least one byte read at each iteration */
  while ( numread > 0 && remain >= 0 )
    {
      aes_encrypt(&aesctr,ptxtbuf,nonce);
      /* xor ctxtbuf and AES(nonce) */
      for (i=0; i<numread; ++i)
	ptxtbuf[i] = ptxtbuf[i] ^ ctxtbuf[i];
      /* add 1 to nonce */
      incrstr(nonce,BLKSIZE);
      /* copy ptxtbuf to outputbuf */
      memcpy(outputbuf,ptxtbuf,numread*sizeof(char));
      /* Compute the AES-CBC-MAC while you go */
      for (i=0; i<BLKSIZE; ++i)
	{
	  if ( i < numread )
	    ctxtbuf[i] = ctxtbuf[i] ^ macbuf[i];
	  else if ( i >= numread )
	    ctxtbuf[i] = 0;
	}
      aes_encrypt(&aescbcmac,macbuf,ctxtbuf);
      /* increment outputbuf */
      outputbuf += numread;
      totalread += BLKSIZE;
      /* read next chunk */
      if ( BLKSIZE > remain )
	numread = read(fin,ctxtbuf,remain);
      else
	numread = read(fin,ctxtbuf,BLKSIZE);
      remain -= numread;
      totalread += numread;
    }
  /* compare aes-cbc-mac's */
  for (i=0; i<BLKSIZE; ++i)
    {
      if (macbuf[i] != actmac[i])
	macchk = 0;
    }
  /*write out outputbuf to ptxt file */
  if ( macchk != 1 )
    puts("MAC mismatch");
  if ( macchk != 1 || (n = write(ptxtfd,outputbak,finsize-(2*BLKSIZE)) ) < 0)
    puts("failed to write ptxt");
  /* clean up! */
  memset(outputbak,0,finsize*sizeof(char));
  memset(ptxtbuf,0,BLKSIZE*sizeof(char));
  memset(ctxtbuf,0,BLKSIZE*sizeof(char));
  memset(macbuf,0,BLKSIZE*sizeof(char));
  memset(actmac,0,BLKSIZE*sizeof(char));
  memset(ctrkey,0,CCA_STRENGTH*sizeof(char));
  memset(mackey,0,CCA_STRENGTH*sizeof(char));
  memset(nonce,0,BLKSIZE*sizeof(char));
  aes_clrkey(&aesctr);
  aes_clrkey(&aescbcmac);
  free(outputbak);
  free(ptxtbuf);
  free(ctxtbuf);
  free(ctrkey);
  free(macbuf);
  free(actmac);
  free(mackey);
  free(nonce);
  outputbak = NULL;
  outputbuf = NULL;
  ptxtbuf   = NULL;
  ctxtbuf   = NULL;
  ctrkey    = NULL;
  macbuf    = NULL;
  actmac    = NULL;
  mackey    = NULL;
  nonce     = NULL;
  close(ptxtfd);
}

void usage(const char *pname)
{
  printf ("Simple File Decryption Utility\n");
  printf ("Usage: %s SK-FILE CTEXT-FILE PTEXT-FILE\n", pname);
  printf ("       Exits if either SK-FILE or CTEXT-FILE don't exist, or\n");
  printf ("       if a symmetric key sk cannot be found in SK-FILE.\n");
  printf ("       Otherwise, tries to use sk to decrypt the content of\n");
  printf ("       CTEXT-FILE: upon success, places the resulting plaintext\n");
  printf ("       in PTEXT-FILE; if a decryption problem is encountered\n"); 
  printf ("       after the processing started, PTEXT-FILE is truncated\n");
  printf ("       to zero-length and its previous content is lost.\n");

  exit (1);
}

int main(int argc, char **argv)
{
  int fdsk, fdctxt;
  char *sk = NULL;
  size_t sk_len = 0;

  if (argc != 4) {
    usage (argv[0]);
  }   /* Check if argv[1] and argv[2] are existing files */
  else if (((fdsk = open (argv[1], O_RDONLY)) == -1)
	   || ((fdctxt = open (argv[2], O_RDONLY)) == -1)) {
    if (errno == ENOENT) {
      usage (argv[0]);
    }
    else {
      perror (argv[0]);
      exit (-1);
    }
  }   
  else {
    setprogname (argv[0]);
    /* Import symmetric key from argv[1] */
    if (!(sk = import_sk_from_file (&sk, &sk_len, fdsk))) {
      printf ("%s: no symmetric key found in %s\n", argv[0], argv[1]); 
      close (fdsk);
      exit (2);
    }
    close (fdsk);
    /* Enough setting up---let's get to the crypto... */
    decrypt_file (argv[3], sk, sk_len, fdctxt);    
    /* scrub the buffer that's holding the key before exiting */
    memset(sk,0,sk_len);
    free(sk);
    sk = NULL;
    close (fdctxt);
  }

  return 0;
}
