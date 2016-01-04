#include "skgu.h"

#define DEFAULT_LABEL "skgu_key"

struct rawpub {
  mpz_t p;			/* Prime */
  mpz_t q;			/* Order */
  mpz_t g;			/* Element of given order */
  mpz_t y;			/* g^x mod p */
};
typedef struct rawpub rawpub;

struct rawpriv {
  mpz_t p;			/* Prime */
  mpz_t q;			/* Order */
  mpz_t g;			/* Element of given order */
  mpz_t x;			/* x mod q */
};
typedef struct rawpriv rawpriv;

int 
get_rawpub (rawpub *rpub_ptr, dckey *pub) {
  const char *pub_as_str = (const char *) dcexport (pub);

  if (skip_str (&pub_as_str, ELGAMAL_STR)
      || skip_str (&pub_as_str, ":Pub,p="))
    return -1;

  mpz_init (rpub_ptr->p);
  mpz_init (rpub_ptr->q);
  mpz_init (rpub_ptr->g);
  mpz_init (rpub_ptr->y);

  if (read_mpz (&pub_as_str, rpub_ptr->p)
      || skip_str (&pub_as_str, ",q=")
      || read_mpz (&pub_as_str, rpub_ptr->q)
      || skip_str (&pub_as_str, ",g=")
      || read_mpz (&pub_as_str, rpub_ptr->g)
      || skip_str (&pub_as_str, ",y=")
      || read_mpz (&pub_as_str, rpub_ptr->y)) {
    return -1;
  }

  return 0;
}

int 
get_rawpriv (rawpriv *rpriv_ptr, dckey *priv) {
  const char *priv_as_str = (const char *) dcexport (priv);

  if (skip_str (&priv_as_str, ELGAMAL_STR)
      || skip_str (&priv_as_str, ":Priv,p="))
    return -1;

  mpz_init (rpriv_ptr->p);
  mpz_init (rpriv_ptr->q);
  mpz_init (rpriv_ptr->g);
  mpz_init (rpriv_ptr->x);

  if (read_mpz (&priv_as_str, rpriv_ptr->p)
      || skip_str (&priv_as_str, ",q=")
      || read_mpz (&priv_as_str, rpriv_ptr->q)
      || skip_str (&priv_as_str, ",g=")
      || read_mpz (&priv_as_str, rpriv_ptr->g)
      || skip_str (&priv_as_str, ",x=")
      || read_mpz (&priv_as_str, rpriv_ptr->x)) {
    return -1;
  }

  return 0;
}

void 
usage (const char *pname)
{
  printf ("Simple Shared-Key Generation Utility\n");
  printf ("Usage: %s PRIV-FILE PRIV-CERT PRIV-ID PUB-FILE PUB-CERT PUB-ID [LABEL]\n", pname);
  exit (-1);
}

void
nidh (dckey *priv, dckey *pub, char *priv_id, char *pub_id, char *label)
{
  rawpriv rpriv;
  rawpub rpub;
  mpz_t dhsecret;
  /*program segfaults if this is not intially set to NULL...*/
  char *dhhexrep = NULL;
  char *fst_id = NULL, *snd_id = NULL;
  char *sha1input;
  char str1[] = "AES-CTR";
  char str2[] = "CBC-MAC";
  char *outfname;
  char fileext[] = ".b64";
  int sha1inputlen;
  int i;
  int j;
  int k;
  void *Km_raw;
  char *Ks0_raw;
  char *Ks1_raw;
  char *Ks_raw;
  char *Ks0_in;
  char *Ks1_in;
  mpz_init(dhsecret);
  Km_raw  = malloc(20);
  Ks0_raw = (char *)malloc(20);
  Ks1_raw = (char *)malloc(20);
  Ks0_in  = (char *)malloc((strlen(label)+7)*sizeof(char));
  Ks1_in  = (char *)malloc((strlen(label)+7)*sizeof(char));
  Ks_raw  = (char *)malloc(32);

  /* step 0: check that the private and public keys are compatible,
     i.e., they use the same group parameters */
  
  if ((-1 == get_rawpub (&rpub, pub)) 
      || (-1 == get_rawpriv (&rpriv, priv))) {
    printf ("%s: trouble importing GMP values from ElGamal-like keys\n",
	    getprogname ());
    
    printf ("priv:\n%s\n", dcexport_priv (priv));
    printf ("pub:\n%s\n", dcexport_pub (pub));

    exit (-1);    
  } else if (mpz_cmp (rpub.p, rpriv.p)
	     || mpz_cmp (rpub.q, rpriv.q)
	     || mpz_cmp (rpub.g, rpriv.g)) {
    printf ("%s:  the private and public keys are incompatible\n",
	    getprogname ());
    
    printf ("priv:\n%s\n", dcexport_priv (priv));
    printf ("pub:\n%s\n", dcexport_pub (pub));

    exit (-1);
  } else {
    
    /* step 1a: compute the Diffie-Hellman secret
                (use mpz_init, mpz_powm, mpz_clear; look at elgamal.c in 
                 the libdcrypt source directory for sample usage 
     */
    
    /* dhsecret = y^x mod p */
    mpz_powm(dhsecret, rpub.y, rpriv.x, rpriv.p);
    /* store dhsecret in dhresult as hex-representation for easier hashing*/
    cat_mpz(&dhhexrep,dhsecret);

    /* step 1b: order the IDs lexicographically */    
    if (strcmp (priv_id, pub_id) < 0) {
      fst_id = priv_id;
      snd_id = pub_id;
    } else {
      fst_id = pub_id;
      snd_id = priv_id;
    }

    /* step 1c: hash DH secret and ordered id pair into a master key */
    sha1inputlen = strlen(dhhexrep) + strlen(fst_id) + strlen(snd_id);
    sha1input = (char *)malloc(sha1inputlen*sizeof(char));
    memset(sha1input,0,sha1inputlen);
    /* copy dhhexrep, fst_id, snd_id into sha1input */
    for (i=0; dhhexrep[i] != '\0'; ++i)
      sha1input[i] = dhhexrep[i];
    for (j=0; fst_id[j] != '\0'; ++i,++j)
      sha1input[i] = fst_id[j];
    for (k=0; snd_id[k] != '\0'; ++i,++k)
      sha1input[i] = snd_id[k];
    sha1input[i] = '\0';
    /* hash to get Km_raw */
    sha1_hash(Km_raw,sha1input,i);

    /* step 2: derive the shared key from the label and the master key */
    for (i=0; label[i] != '\0'; ++i)
      Ks0_in[i] = label[i];
    for (j=0; str1[j] != '\0'; ++i,++j)
      Ks0_in[i] = str1[j];
    hmac_sha1(Km_raw,20,Ks0_raw,Ks0_in,strlen(label)+7);

    for (i=0; label[i] != '\0'; ++i)
      Ks1_in[i] = label[i];
    for (j=0; str2[j] != '\0'; ++i,++j)
      Ks1_in[i] = str2[j];
    hmac_sha1(Km_raw,20,Ks1_raw,Ks1_in,strlen(label)+7);

    for (i=0; i<16; ++i)
      Ks_raw[i] = Ks0_raw[i];
    for (j=0; i<32; ++i,++j)
      Ks_raw[i] = Ks1_raw[j];
    
    /*Ks_raw is now 32 bytes long and ready for armoring */

    /* step 3: armor the shared key and write it to file.
       Filename should be of the form <label>-<priv_id>.b64 */
    outfname = (char *)malloc( (strlen(label)+strlen(priv_id)+5) * sizeof(char) );
    for (i=0; label[i] != '\0'; ++i)
      outfname[i] = label[i];
    outfname[i++] = '-';
    for (j=0; priv_id[j] != '\0'; ++i,++j)
      outfname[i] = priv_id[j];
    for (k=0; fileext[k] != '\0'; ++i,++k)
      outfname[i] = fileext[k];
    outfname[i] = '\0';
    
    write_skfile(outfname, Ks_raw, 32);
    
    /* clear memory */
    mpz_clear(rpriv.x);
    mpz_clear(dhsecret);
    memset(dhhexrep,0,strlen(dhhexrep));
    memset(sha1input,0,strlen(sha1input));
    memset(Km_raw,0,20);
    memset(Ks0_raw,0,20);
    memset(Ks1_raw,0,20);
    memset(Ks0_in,0,20);
    memset(Ks1_in,0,20);
    memset(Ks_raw,0,32);
    free(dhhexrep);
    free(sha1input);
    free(Km_raw);
    free(Ks0_raw);
    free(Ks1_raw);
    free(Ks0_in);
    free(Ks1_in);
    free(Ks_raw);
    free(outfname);
  }
}

int
main (int argc, char **argv)
{
  int arg_idx = 0;
  char *privcert_file = NULL;
  char *pubcert_file = NULL;
  char *priv_file = NULL;
  char *pub_file = NULL;
  char *priv_id = NULL;
  char *pub_id = NULL;
  char *label = DEFAULT_LABEL;
  dckey *priv = NULL;
  dckey *pub = NULL;
  cert *priv_cert = NULL;
  cert *pub_cert = NULL;

  if ((7 > argc) || (8 < argc))    usage (argv[0]);

  ri ();

  priv_file = argv[++arg_idx];
  privcert_file = argv[++arg_idx];
  priv_id = argv[++arg_idx];
  pub_file  = argv[++arg_idx];
  pubcert_file = argv[++arg_idx];
  pub_id = argv[++arg_idx];
  if (argc - 2 == arg_idx) {
    /* there was a label */
    label = argv[++arg_idx];
  }

  pub_cert = pki_check(pubcert_file, pub_file, pub_id);
  /* check above won't return if something was wrong */
  pub = pub_cert->public_key;

  if (!cert_verify (priv_cert = cert_read (privcert_file))) {
      printf ("%s: trouble reading certificate from %s, "
	      "or certificate expired\n", getprogname (), privcert_file);
      perror (getprogname ());

      exit (-1);
  } else if (!dcareequiv(pub_cert->issuer,priv_cert->issuer)) {
    printf ("%s: certificates issued by different CAs.\n",
	    getprogname ());
    printf ("\tOwn (%s's) certificate in %s\n", priv_id, privcert_file);
    printf ("\tOther (%s's) certificate in %s\n", pub_id, pubcert_file);
  } else {
    priv = priv_from_file (priv_file);
    
    nidh (priv, pub, priv_id, pub_id, label);
  }

  return 0;
}
