#include "pv.h"

void write_skfile (const char *skfname, void *raw_sk, size_t raw_sklen)
{
  int fdsk = 0;
  char *s = NULL;
  int status = 0;

  /* armor the raw symmetric key in raw_sk using armor64 */
  s = armor64(raw_sk,raw_sklen);
  /* now let's write the armored symmetric key to skfname */
  if ((fdsk = open(skfname, O_WRONLY|O_TRUNC|O_CREAT, 0600)) == -1)
    {
      perror(getprogname());
      /* scrub the buffers that are holding the keys before exiting */
      memset(raw_sk,0,raw_sklen*sizeof(char));
      free(raw_sk);
      raw_sk = NULL;
      memset(s,0,strlen(s));
      free(s);
      s = NULL;
      exit(-1);
    }
  else
    {
      status = write(fdsk, s, strlen (s));
      if (status != -1)
	{
	  status = write(fdsk, "\n", 1);
	}
      /* scrub local buffer containing armored keys */
      memset(s,0,strlen(s));
      free(s);
      s = NULL;
      close(fdsk);
      
      if (status == -1)
	{
	  printf("%s: trouble writing symmetric key to file %s\n", getprogname(), skfname);
	  perror(getprogname());
	  /* scrub the buffers that are holding the keys before exiting */
	  memset(raw_sk,0,raw_sklen*sizeof(char));
	  free(raw_sk);
	  raw_sk = NULL;
	  memset(s,0,strlen(s));
	  free(s);
	  s = NULL;
	  exit(-1);
	}
    }
}

void usage(const char *pname)
{
  printf("Personal Vault: Symmetric Key Generation\n");
  printf("Usage: %s SK-FILE \n", pname);
  printf("       Generates a new symmetric key, and writes it to\n");
  printf("       SK-FILE.  Overwrites previous file content, if any.\n");
  exit(1);
}

int main(int argc, char **argv)
{
  unsigned int keylen;
  char *keybuf;
  keylen = 2*CCA_STRENGTH;
  keybuf = (char *)malloc(keylen*sizeof(char));
  
  if (argc != 2)
    usage(argv[0]);
  setprogname(argv[0]);
  /* initialize PRNG with random seed */
  ri();
  /* get 32 pseudorandom bytes for keys (16 bytes for AES-CTR key,
     and 16 bytes for AES-CBC-MAC) */
  prng_getbytes(keybuf,keylen);
  /* now let's armor and dump to disk the symmetric key buffer */
  write_skfile(argv[1],keybuf,keylen);
  /* finally, let's scrub the buffer that held the random bits 
     by overwriting with a bunch of 0's */
  memset(keybuf,0,keylen*sizeof(char));
  free(keybuf);
  keybuf = NULL;

  return 0;
}

