#define _POSIX_C_SOURCE 200809L
#include "assembler/assembler.h"
#include <elf.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifndef SHF_GNU_RETAIN
#define SHF_GNU_RETAIN 0x200000
#endif

/* Small native x86-64 AT&T assembler. Emits ELF64 ET_REL, no external assembler. */
typedef struct SourceLocationNode {
 const char *filename;
 size_t line;
 const struct SourceLocationNode *expanded_from;
 unsigned include_depth;
 struct SourceLocationNode *allocated_next;
} SourceLocationNode;
typedef struct { char *text; const SourceLocationNode *location; } SourceLine;
typedef struct SourceFilename {
 char *name;
 struct SourceFilename *next;
} SourceFilename;
static SourceLocationNode *allocated_locations;
static SourceFilename *allocated_filenames;
static const SourceLocationNode *current_location;
static const char *const *assembler_include_dirs;
static size_t assembler_include_count;
static int include_io_error;

typedef struct Sym { char *name; uint64_t value, size; unsigned char bind, type, visibility; int defined, section, local_common, pending_common, signature_group; uint32_t name_offset, elf_index; size_t file_count; struct Sym *next; } Sym;
typedef struct { char *source, *alias; const SourceLocationNode *location; } Symver;
typedef struct { char *name; int kind, reg, width; int base,index,scale,rip,addr32,disp32; int64_t disp; const char *symbol; uint32_t reloc_type; } Op;
typedef struct { Elf64_Rela r; char *sym; int section; } Rel;
typedef struct { int section, width; size_t offset; char *left, *right; int64_t addend; const SourceLocationNode *location; } DiffFixup;
enum { BRANCH_JUMP=1, BRANCH_CONDITIONAL, BRANCH_CALL, BRANCH_LOOP };
typedef struct { int line, section, kind, cc, short_form; size_t insn_offset, field_offset; int field_width; uint32_t reloc_type; char *symbol; int64_t addend; } Branch;
typedef struct { char *name, *expr; int resolved, evaluating, required; int64_t value; const SourceLocationNode *location; } Equ;
#define SEC_CAP (1u<<20)
#define NOBITS_CAP (64u<<20)
static unsigned char text[SEC_CAP], data[SEC_CAP], rodata[SEC_CAP];
static size_t nt, nd, nb, nro, base_align[5];
/* Section ids: 1=.text, 2=.data, 3=.bss, 4=.rodata, 5+ user sections. */
#define MAX_CUSTOM_SECTIONS 16
#define MAX_SECTION_STACK 32
typedef struct { char name[128]; uint64_t flags; uint32_t type; size_t align, size, entsize; int group; const SourceLocationNode *location; unsigned char data[SEC_CAP]; } CustomSection;
typedef struct { char *signature; int comdat; } SectionGroup;
static CustomSection custom_sections[MAX_CUSTOM_SECTIONS];
static size_t ncustom_sections;
static SectionGroup section_groups[MAX_CUSTOM_SECTIONS];
static size_t nsection_groups;
static int section_stack[MAX_SECTION_STACK];
static const SourceLocationNode *section_stack_locations[MAX_SECTION_STACK];
static size_t section_stack_depth;
static int current_section=1;
static unsigned char *section_bytes(void){ if(current_section>=5&&current_section<5+(int)ncustom_sections)return custom_sections[current_section-5].data; return current_section==1?text:current_section==2?data:rodata; }
static size_t *section_size(void){ if(current_section>=5&&current_section<5+(int)ncustom_sections)return &custom_sections[current_section-5].size; return current_section==1?&nt:current_section==2?&nd:current_section==3?&nb:&nro; }
static size_t section_offset(void){ return *section_size(); }
static int section_is_nobits(int sec){ return sec==3 || (sec>=5&&sec<5+(int)ncustom_sections&&custom_sections[sec-5].type==SHT_NOBITS); }
static uint32_t section_type(int sec){ return sec==3?SHT_NOBITS:(sec>=5&&sec<5+(int)ncustom_sections?custom_sections[sec-5].type:SHT_PROGBITS); }
static uint64_t section_flags(int sec){ if(sec==1)return SHF_ALLOC|SHF_EXECINSTR;if(sec==2||sec==3)return SHF_ALLOC|SHF_WRITE;if(sec==4)return SHF_ALLOC;return custom_sections[sec-5].flags; }
static size_t *section_alignment(int sec){ return sec<5?&base_align[sec]:&custom_sections[sec-5].align; }
static size_t section_align(int sec){ return *section_alignment(sec); }
static const char *section_name(int sec){ static const char *base[]={NULL,".text",".data",".bss",".rodata"};return sec<5?base[sec]:custom_sections[sec-5].name; }
static Sym **syms, **symbol_buckets; static size_t ns, symbol_capacity, symbol_bucket_count;
static char **file_symbols; static size_t nfile_symbols, file_symbol_capacity;
typedef struct { Sym *sym; uint64_t size; size_t align; const SourceLocationNode *location; } CommonAllocation;
static CommonAllocation common_allocations[4096]; static size_t ncommon_allocations;
static Rel *rels; static size_t nr, rel_capacity;
static DiffFixup diffs[4096]; static size_t ndiffs;
static Branch branches[16384]; static size_t nbranches;
static Equ equs[4096]; static size_t nequs;
typedef struct { char *name; int64_t value; int known, defined; size_t next; } PreprocessConstant;
static PreprocessConstant *preprocess_constants;
static size_t npreprocess_constants, preprocess_capacity;
static size_t *preprocess_buckets, preprocess_bucket_count;
static PreprocessConstant *preprocess_symbol(const char *name,int create);
static int evaluating_preprocess;
static Symver symvers[4096]; static size_t nsymvers;
static unsigned char *short_lines; static size_t nlines;
static size_t current_line;
static int failed;
static int report_warnings;
static int lock_prefix_active, rep_prefix_active, repne_prefix_active;
static int segment_prefix_emitted;
static size_t instruction_start;
static const char *rnames[64] = {
 "%al","%ax","%eax","%rax", "%cl","%cx","%ecx","%rcx", "%dl","%dx","%edx","%rdx", "%bl","%bx","%ebx","%rbx",
 "%spl","%sp","%esp","%rsp", "%bpl","%bp","%ebp","%rbp", "%sil","%si","%esi","%rsi", "%dil","%di","%edi","%rdi",
 "%r8b","%r8w","%r8d","%r8", "%r9b","%r9w","%r9d","%r9", "%r10b","%r10w","%r10d","%r10", "%r11b","%r11w","%r11d","%r11",
 "%r12b","%r12w","%r12d","%r12", "%r13b","%r13w","%r13d","%r13", "%r14b","%r14w","%r14d","%r14", "%r15b","%r15w","%r15d","%r15"
};
static int add_overflow64(int64_t a,int64_t b,int64_t *out){
 if((b>0&&a>INT64_MAX-b)||(b<0&&a<INT64_MIN-b))return 1;
 *out=a+b;return 0;
}
static int sub_overflow64(int64_t a,int64_t b,int64_t *out){
 if((b<0&&a>INT64_MAX+b)||(b>0&&a<INT64_MIN+b))return 1;
 *out=a-b;return 0;
}
static int mul_overflow64(int64_t a,int64_t b,int64_t *out){
 if((a>0&&((b>0&&a>INT64_MAX/b)||(b<0&&b<INT64_MIN/a)))||
    (a<0&&((b>0&&a<INT64_MIN/b)||(b<0&&a<INT64_MAX/b))))return 1;
 *out=a*b;return 0;
}
static void report_io_error(const char *name){
 if(name&&*name)fprintf(stderr,"%s: %s\n",name,strerror(errno));
 else fprintf(stderr,"%s\n",strerror(errno));
}
static void err(const char *s){
 if(current_location){
  fprintf(stderr,"crunch-as: %s:%zu: error: %s\n",current_location->filename,current_location->line,s);
  for(const SourceLocationNode *p=current_location->expanded_from;p;p=p->expanded_from)
   fprintf(stderr,"crunch-as: %s:%zu: note: expanded from here\n",p->filename,p->line);
 }else fprintf(stderr,"crunch-as: %s\n",s);
 failed=1;
}
static const char *intern_filename(const char *name){
 for(SourceFilename *p=allocated_filenames;p;p=p->next)if(!strcmp(p->name,name))return p->name;
 SourceFilename *p=malloc(sizeof *p);
 if(!p){err("out of memory tracking source filenames");return NULL;}
 p->name=strdup(name);
 if(!p->name){free(p);err("out of memory tracking source filenames");return NULL;}
 p->next=allocated_filenames;allocated_filenames=p;return p->name;
}
static const SourceLocationNode *source_location(const char *filename,size_t line,
                                                  const SourceLocationNode *expanded_from,
                                                  unsigned include_depth){
 SourceLocationNode *p=malloc(sizeof *p);
 if(!p){err("out of memory tracking source locations");return NULL;}
 *p=(SourceLocationNode){filename,line,expanded_from,include_depth,allocated_locations};
 allocated_locations=p;return p;
}
static void emit(uint64_t v,int n){ size_t *sz=section_size(); size_t cap=section_is_nobits(current_section)?NOBITS_CAP:SEC_CAP; if(*sz>cap||(size_t)n>cap-*sz){err("section too large");return;} if(section_is_nobits(current_section)){if(v){err("cannot emit nonzero initialized bytes in NOBITS section");return;}*sz+=(size_t)n;return;} unsigned char *buf=section_bytes(); for(int i=0;i<n;i++) buf[(*sz)++]=(unsigned char)(v>>(8*i)); }
static void insert_instruction_prefix(unsigned char prefix,size_t offset){
 size_t end=section_offset();
 emit(prefix,1);if(failed)return;
 unsigned char *buf=section_bytes();
 memmove(buf+offset+1,buf+offset,end-offset);
 buf[offset]=prefix;
}
static char *trim(char *s){ while(isspace((unsigned char)*s))s++; size_t n=strlen(s);while(n&&isspace((unsigned char)s[n-1]))s[--n]=0;return s; }
static void strip_comment(char *s){
 int quote=0,escape=0;
 for(;*s;s++){
  if(escape){escape=0;continue;}
  if(quote&&*s=='\\'){escape=1;continue;}
  if(quote){if(*s==quote)quote=0;continue;}
  if(*s=='"'||*s=='\'')quote=*s;
  else if(*s=='#'){*s=0;return;}
 }
}
static int regparse(const char *s,int *w){ for(int r=0;r<16;r++)for(int k=0;k<4;k++)if(!strcmp(s,rnames[r*4+k])){*w=8<<k;return r;} return -1; }
static int xmmparse(const char *s){
 if(strncmp(s,"%xmm",4)||!isdigit((unsigned char)s[4]))return -1;
 char *end;long n=strtol(s+4,&end,10);
 return *end||n<0||n>15?-1:(int)n;
}
static size_t symbol_hash(const char *name){
 size_t hash=5381;for(;*name;name++)hash=hash*33+(unsigned char)*name;return hash;
}
static Sym *find_symbol(const char *name){
 if(!symbol_bucket_count)return NULL;
 for(Sym *s=symbol_buckets[symbol_hash(name)%symbol_bucket_count];s;s=s->next)
  if(!strcmp(s->name,name))return s;
 return NULL;
}
static Sym *symget(const char *name){
 Sym *s=find_symbol(name);if(s)return s;
 if(ns>=UINT32_MAX-1){err("too many symbols");return NULL;}
 if(ns==symbol_capacity){
  if(symbol_capacity>SIZE_MAX/2/sizeof *syms){err("too many symbols");return NULL;}
  size_t capacity=symbol_capacity?symbol_capacity*2:64;
  Sym **items=realloc(syms,capacity*sizeof *items);
  if(!items){err("out of memory recording symbol");return NULL;}
  syms=items;symbol_capacity=capacity;
 }
 if(ns>=symbol_bucket_count){
  if(symbol_bucket_count>SIZE_MAX/2/sizeof *symbol_buckets){err("too many symbols");return NULL;}
  size_t count=symbol_bucket_count?symbol_bucket_count*2:64;
  Sym **buckets=calloc(count,sizeof *buckets);
  if(!buckets){err("out of memory recording symbol");return NULL;}
  for(size_t i=0;i<ns;i++){
   size_t slot=symbol_hash(syms[i]->name)%count;
   syms[i]->next=buckets[slot];buckets[slot]=syms[i];
  }
  free(symbol_buckets);symbol_buckets=buckets;symbol_bucket_count=count;
 }
 s=calloc(1,sizeof *s);if(!s){err("out of memory recording symbol");return NULL;}
 s->name=strdup(name);if(!s->name){free(s);err("out of memory recording symbol");return NULL;}
 s->bind=STB_LOCAL;
 s->file_count=nfile_symbols;
 size_t slot=symbol_hash(name)%symbol_bucket_count;
 s->next=symbol_buckets[slot];symbol_buckets[slot]=s;syms[ns++]=s;return s;
}
static int64_t number(const char *s,int *ok){char *e; errno=0; intmax_t v=strtoimax(s,&e,0);*ok=(*s&&!*e&&!errno);return (int64_t)v;}
static int expr_ident_start(unsigned char c){ return isalpha(c)||c=='_'||c=='.'||c=='$'; }
static int expr_ident_char(unsigned char c){ return isalnum(c)||c=='_'||c=='.'||c=='$'; }
static int valid_symbol_name(const char *s){
 if(!expr_ident_start((unsigned char)*s++))return 0;
 while(*s)if(!expr_ident_char((unsigned char)*s++))return 0;
 return 1;
}
static int valid_symver_alias(const char *s){
 if(!expr_ident_start((unsigned char)*s++))return 0;
 while(expr_ident_char((unsigned char)*s))s++;
 if(*s++!='@')return 0;
 if(s[0]=='@'&&s[1]=='@')return 0;
 while(*s){if(*s!='@'&&!expr_ident_char((unsigned char)*s))return 0;s++;}
 return 1;
}
static int signed_addend(char sign,const char *s,int64_t *value){
 if(!isdigit((unsigned char)*s))return 0;
 errno=0;char *end;uintmax_t n=strtoumax(s,&end,0);
 if(errno||*end||n>(uint64_t)INT64_MAX+(sign=='-'))return 0;
 *value=sign=='-'?(n?-1-(int64_t)(n-1):0):(int64_t)n;
 return 1;
}
/* The name borrows the mutable operand buffer; deferred records copy it. */
static int symbol_expr(char *s, const char **name, int64_t *addend){
 s=trim(s);if(!expr_ident_start((unsigned char)*s))return 0;
 char *end=s+1;while(expr_ident_char((unsigned char)*end))end++;
 char *tail=trim(end);int64_t value=0;
 if(*tail){
  char sign=*tail++;
  if((sign!='+'&&sign!='-')||!signed_addend(sign,trim(tail),&value))return 0;
 }
 *end=0;*name=s;*addend=value;return 1;
}
typedef struct { const char *p; int ok; unsigned depth; } ExprParser;
static int eval_absolute(const char *expr, int64_t *value);
static int expr_parse_or(ExprParser *p, int64_t *v);
static int expr_space(ExprParser *p){ while(isspace((unsigned char)*p->p))p->p++; return 1; }
static int expr_primary(ExprParser *p, int64_t *v){
 expr_space(p);
 if(*p->p=='('){p->p++; if(!expr_parse_or(p,v))return 0;expr_space(p);if(*p->p!=')'){p->ok=0;return 0;}p->p++;return 1;}
 if(*p->p=='\''){
  const char *q=++p->p;if(!*q||*q=='\n'||*q=='\''){p->ok=0;return 0;}
  unsigned char c=(unsigned char)*q++;
  if(c=='\\'){
   if(!*q){p->ok=0;return 0;}c=(unsigned char)*q++;
   if(c=='n')c='\n';else if(c=='t')c='\t';else if(c=='r')c='\r';else if(c=='0')c=0;
  }
  if(*q!='\''){p->ok=0;return 0;}
  p->p=q+1;*v=c;return 1;
 }
 if(isdigit((unsigned char)*p->p)){
  errno=0;char *e=NULL;intmax_t n=strtoimax(p->p,&e,0);
  if(e==p->p||errno){p->ok=0;return 0;}*v=(int64_t)n;p->p=e;return 1;
 }
 if(expr_ident_start((unsigned char)*p->p)){
  const char *b=p->p;while(expr_ident_char((unsigned char)*p->p))p->p++;
  size_t n=(size_t)(p->p-b);char name[256];if(!n||n>=sizeof name){p->ok=0;return 0;}memcpy(name,b,n);name[n]=0;
  if(evaluating_preprocess){
   PreprocessConstant *constant=preprocess_symbol(name,0);
   if(constant&&constant->known){*v=constant->value;return 1;}
   p->ok=0;return 0;
  }
  Sym *sym=find_symbol(name);
  if(sym&&sym->defined&&sym->section==SHN_ABS){*v=(int64_t)sym->value;return 1;}
  for(size_t i=0;i<nequs;i++)if(!strcmp(equs[i].name,name)){
   Equ *e=&equs[i];if(e->resolved){*v=e->value;return 1;}if(e->evaluating||p->depth>128){p->ok=0;return 0;}
   e->evaluating=1;p->depth++;int good=eval_absolute(e->expr,v);p->depth--;e->evaluating=0;
   if(good){e->resolved=1;e->value=*v;Sym *es=symget(e->name);if(!es)return 0;es->defined=1;es->section=SHN_ABS;es->value=(uint64_t)*v;return 1;}
   p->ok=0;return 0;
  }
  p->ok=0;return 0;
 }
 p->ok=0;return 0;
}
static int expr_unary(ExprParser *p,int64_t *v){
 expr_space(p);char op=*p->p;
 if(op=='+'||op=='-'||op=='~'){
  p->p++;int64_t a;if(!expr_unary(p,&a))return 0;
  if(op=='-'){if(a==INT64_MIN){p->ok=0;return 0;}*v=-a;}else if(op=='~')*v=~a;else *v=a;return 1;
 }
 return expr_primary(p,v);
}
static int expr_mul(ExprParser *p,int64_t *v){
 if(!expr_unary(p,v))return 0;
 for(;;){expr_space(p);char op=*p->p;if(op!='*'&&op!='/'&&op!='%')return 1;p->p++;int64_t b,r;if(!expr_unary(p,&b))return 0;
  if(op=='*'){if(mul_overflow64(*v,b,&r)){p->ok=0;return 0;}}
  else {if(!b||(*v==INT64_MIN&&b==-1)){p->ok=0;return 0;}r=op=='/'?*v/b:*v%b;}*v=r;
 }
}
static int expr_add(ExprParser *p,int64_t *v){if(!expr_mul(p,v))return 0;for(;;){expr_space(p);char op=*p->p;if(op!='+'&&op!='-')return 1;p->p++;int64_t b,r;if(!expr_mul(p,&b))return 0;if(op=='+'){if(add_overflow64(*v,b,&r)){p->ok=0;return 0;}}else if(sub_overflow64(*v,b,&r)){p->ok=0;return 0;}*v=r;}}
static int expr_shift(ExprParser *p,int64_t *v){if(!expr_add(p,v))return 0;for(;;){expr_space(p);int left=p->p[0]=='<'&&p->p[1]=='<';int right=p->p[0]=='>'&&p->p[1]=='>';if(!left&&!right)return 1;p->p+=2;int64_t b;if(!expr_add(p,&b)||b<0||b>63){p->ok=0;return 0;}if(left){if(*v<0||(*v && (uint64_t)*v>(uint64_t)INT64_MAX>>(unsigned)b)){p->ok=0;return 0;}*v=(int64_t)((uint64_t)*v<<(unsigned)b);}else *v >>= (unsigned)b;}}
static int expr_and(ExprParser *p,int64_t *v){if(!expr_shift(p,v))return 0;for(;;){expr_space(p);if(p->p[0]!='&'||p->p[1]=='&')return 1;p->p++;int64_t b;if(!expr_shift(p,&b))return 0;*v&=b;}}
static int expr_xor(ExprParser *p,int64_t *v){if(!expr_and(p,v))return 0;for(;;){expr_space(p);if(*p->p!='^')return 1;p->p++;int64_t b;if(!expr_and(p,&b))return 0;*v^=b;}}
static int expr_parse_or(ExprParser *p,int64_t *v){if(!expr_xor(p,v))return 0;for(;;){expr_space(p);if(p->p[0]!='|'||p->p[1]=='|')return 1;p->p++;int64_t b;if(!expr_xor(p,&b))return 0;*v|=b;}}
static int eval_absolute(const char *expr,int64_t *value){ExprParser p={.p=expr,.ok=1};int64_t v;if(!expr_parse_or(&p,&v))return 0;expr_space(&p);if(*p.p||!p.ok)return 0;*value=v;return 1;}
static int resolve_absolute_expr(const char *expr, int64_t *value){ return eval_absolute(expr,value); }

static int collect_equations(SourceLine *lines, size_t count){
 /* Seed forward references with each symbol's first absolute assignment. */
 for(size_t i=0;i<count;i++){
  current_location=lines[i].location;
  char *copy=strdup(lines[i].text); if(!copy){err("out of memory collecting .equ definitions");return 0;}
  char *p=trim(copy);strip_comment(p);p=trim(p);
  char *colon=strchr(p,':'),*space=p;
  while(*space&&!isspace((unsigned char)*space))space++;
  if(colon&&colon<space)p=trim(colon+1);
  int is_equ=!strncmp(p,".equ",4)&&isspace((unsigned char)p[4]);
  int is_set=!strncmp(p,".set",4)&&isspace((unsigned char)p[4]);
  if(!is_equ&&!is_set){free(copy);continue;}
  p=trim(p+4); char *comma=strchr(p,',');
  if(!comma){err(is_equ?".equ expects symbol,expression":".set expects symbol,expression");free(copy);return 0;}
  *comma=0; char *name=trim(p), *expr=trim(comma+1);
  if(!valid_symbol_name(name)||!*expr){err(is_equ?".equ expects a valid symbol and expression":".set expects a valid symbol and expression");free(copy);return 0;}
  size_t j=0;while(j<nequs&&strcmp(equs[j].name,name))j++;
  if(j<nequs){free(copy);continue;}
  if(nequs==sizeof equs/sizeof equs[0]){err("too many .equ definitions");free(copy);return 0;}
  equs[nequs++]=(Equ){.name=strdup(name),.expr=strdup(expr),.required=is_equ,.location=current_location};
  if(!equs[nequs-1].name||!equs[nequs-1].expr){err("out of memory collecting .equ definitions");free(copy);return 0;}
  free(copy);
 }
 return 1;
}
static void load_equations(void){
 for(size_t i=0;i<nequs;i++){equs[i].resolved=0;equs[i].evaluating=0;}
 size_t unresolved=nequs;
 for(size_t pass=0;pass<=nequs&&unresolved;pass++){
  size_t previous=unresolved;
  for(size_t i=0;i<nequs;i++) if(!equs[i].resolved){
   current_location=equs[i].location;
   int64_t value;
   if(resolve_absolute_expr(equs[i].expr,&value)){
    Sym *sym=symget(equs[i].name); if(!sym)return;
    sym->defined=1; sym->section=SHN_ABS; sym->value=(uint64_t)value;
    equs[i].value=value; equs[i].resolved=1;
   }
  }
  unresolved=0;for(size_t i=0;i<nequs;i++)if(!equs[i].resolved)unresolved++;
  if(unresolved==previous)break;
 }
 if(unresolved){
  for(size_t i=0;i<nequs;i++) if(!equs[i].resolved&&equs[i].required){
   char message[512];current_location=equs[i].location;
   snprintf(message,sizeof message,"unresolved or cyclic .equ definition: %s = %s",equs[i].name,equs[i].expr);
   err(message);
  }
 }
}

static uint32_t relocation_modifier_type(const char *kind){
 if(!strcmp(kind,"TLSGD")) return R_X86_64_TLSGD;
 if(!strcmp(kind,"TLSLD")) return R_X86_64_TLSLD;
 if(!strcmp(kind,"GOTTPOFF")) return R_X86_64_GOTTPOFF;
 if(!strcmp(kind,"TLSDESC")) return R_X86_64_GOTPC32_TLSDESC;
 if(!strcmp(kind,"TLSCALL")) return R_X86_64_TLSDESC_CALL;
 if(!strcmp(kind,"PLT")) return R_X86_64_PLT32;
 if(!strcmp(kind,"GOTPCREL")) return R_X86_64_GOTPCREL;
 if(!strcmp(kind,"TPOFF")) return R_X86_64_TPOFF32;
 if(!strcmp(kind,"DTPOFF")) return R_X86_64_DTPOFF32;
 if(!strcmp(kind,"DTPMOD")) return R_X86_64_DTPMOD64;
 return 0;
}
static int split_relocation_modifier(char *expr,uint32_t *type){
 char *at=strrchr(expr,'@'); if(!at)return 0;
 uint32_t t=relocation_modifier_type(at+1);
 if(!t){err("unsupported relocation modifier");return -1;}
 *at=0; if(!*trim(expr)){err("relocation modifier requires a symbol");return -1;}
 *type=t;return 1;
}
static int parse_integer_bits(const char *text,int64_t *value){
 int negative=0;
 if(*text=='+'||*text=='-'){negative=*text=='-';text++;}
 if(!isdigit((unsigned char)*text))return 0;
 char *end;errno=0;uintmax_t n=strtoumax(text,&end,0);
 if(errno==ERANGE||*end||n>UINT64_MAX||(negative&&n>(uint64_t)INT64_MAX+1))return -1;
 if(negative)*value=n?-1-(int64_t)(n-1):0;
 else if(n<=INT64_MAX)*value=(int64_t)n;
 else *value=-1-(int64_t)(UINT64_MAX-(uint64_t)n);
 return 1;
}
static int parse_memory_expression(char *s,Op *o){
 s=trim(s);
 if(!*s)return 0;
 if(resolve_absolute_expr(s,&o->disp))return 1;
 while(*s=='('){
  int depth=0;char *end=NULL;
  for(char *p=s;*p;p++){
   if(*p=='(')depth++;
   else if(*p==')'&&!--depth){end=p;break;}
  }
  if(!end||end[1])break;
  *end=0;s=trim(s+1);
  if(!*s)return 0;
  if(resolve_absolute_expr(s,&o->disp))return 1;
 }
 int numeric=parse_integer_bits(s,&o->disp);
 if(numeric)return numeric>0;
 int mr=split_relocation_modifier(s,&o->reloc_type);if(mr<0)return 0;
 return symbol_expr(s,&o->symbol,&o->disp);
}
static int parseop(char *s,Op *o){ memset(o,0,sizeof *o);o->base=o->index=-1;o->scale=1; s=trim(s);
 /* AT&T segment overrides precede address-size and instruction prefixes. */
 if(!strncmp(s,"%fs:",4)||!strncmp(s,"%gs:",4)){
   if(segment_prefix_emitted){err("only one segment override is supported per instruction");return 0;}
   insert_instruction_prefix(s[1]=='f'?0x64:0x65,instruction_start);segment_prefix_emitted=1;s=trim(s+4);
 }
 if(*s=='$'){
   o->kind=1;if(resolve_absolute_expr(s+1,&o->disp))return 1;
   if(s[1]=='\''){err("invalid character immediate");return 0;}
   int numeric=parse_integer_bits(s+1,&o->disp);
   if(numeric<0){err("invalid or out-of-range integer immediate");return 0;}
   if(numeric>0)return 1;
   return symbol_expr(s+1,&o->symbol,&o->disp);
 }
 int w=0,r=regparse(s,&w);if(r>=0){o->kind=2;o->reg=r;o->width=w;return 1;}
 r=xmmparse(s);if(r>=0){o->kind=4;o->reg=r;o->width=128;return 1;}
 if(*s=='%')return 0; /* Unknown register-like tokens must not become symbols. */
 o->kind=3;if(!*s)return 0;
 char *lp=NULL,*rp=NULL;int depth=0,quote=0,escape=0;
 for(char *p=s;*p;p++){
  if(quote){if(escape)escape=0;else if(*p=='\\')escape=1;else if(*p==quote)quote=0;continue;}
  if(*p=='\''||*p=='"'){quote=*p;continue;}
  if(*p=='('){if(!depth)lp=p;depth++;}
  else if(*p==')'){if(!depth)return 0;depth--;if(!depth)rp=p;}
 }
 if(depth||quote)return 0;
 char *inside=lp?trim(lp+1):NULL;
 if(!lp||!rp||rp[1]||(*inside!='%'&&*inside!=','&&*inside!=')')){
  if(!parse_memory_expression(s,o))return 0;
 }else{
  *lp=0;*rp=0;char *d=trim(s);if(*d&&!parse_memory_expression(d,o))return 0;
  char *parts[3]={lp+1,NULL,NULL};int np=1;
  for(char *p=lp+1;*p;p++)if(*p==','){
   if(np==3)return 0;
   *p=0;parts[np++]=p+1;
  }
  for(int i=0;i<np;i++)parts[i]=trim(parts[i]);
  int address_width=0;
  if(*parts[0]){
   int ww=0;
   if(!strcmp(parts[0],"%rip")||!strcmp(parts[0],"%eip")){
    o->rip=1;address_width=parts[0][1]=='e'?32:64;
   }else{
    o->base=regparse(parts[0],&ww);
    if(o->base<0||(ww!=32&&ww!=64))return 0;
    address_width=ww;
   }
  }
  if(np>1){
   int ww;if(!*parts[1])return 0;
   o->index=regparse(parts[1],&ww);
   if(o->index<0||(ww!=32&&ww!=64)||o->index==4||o->rip||
      (address_width&&address_width!=ww))return 0;
   address_width=ww;
  }
  o->addr32=address_width==32;
  if(o->base<0&&!o->rip&&o->index<0)return 0;
  if(np>2&&*parts[2]){int64_t v;if(!resolve_absolute_expr(parts[2],&v)||(v!=1&&v!=2&&v!=4&&v!=8))return 0;o->scale=(int)v;}
 }
 if(o->reloc_type==R_X86_64_TLSDESC_CALL){
   if(o->rip||o->addr32||o->base!=0||o->index>=0||o->symbol==NULL||o->disp!=0){err("@TLSCALL requires a symbol with (%rax) and no displacement or index");return 0;}
 } else if(o->reloc_type&&!o->rip&&o->reloc_type!=R_X86_64_DTPOFF32&&o->reloc_type!=R_X86_64_TPOFF32){err("this relocation modifier requires RIP-relative memory or a supported TLS offset base");return 0;}
 if(o->addr32){
  if(!o->symbol){
   o->disp32=o->disp<INT32_MIN||o->disp>UINT32_MAX;
   uint32_t bits=(uint32_t)o->disp;
   o->disp=bits<=INT32_MAX?(int64_t)bits:-1-(int64_t)(UINT32_MAX-bits);
  }
  insert_instruction_prefix(0x67,instruction_start+(segment_prefix_emitted?1:0));
 }
 return 1;
}
static void relocation_at(const char *s,uint32_t type,int64_t add,int section,size_t offset){
 if(!s)return;
 if(!symget(s))return;
 if(type==R_X86_64_GOTPCREL||type==R_X86_64_GOTPCRELX||type==R_X86_64_REX_GOTPCRELX){
  Sym *got=symget("_GLOBAL_OFFSET_TABLE_");if(!got)return;
  if(!got->defined&&got->bind==STB_LOCAL)got->bind=STB_GLOBAL;
 }
 if(nr==rel_capacity){
  if(rel_capacity>SIZE_MAX/2/sizeof *rels){err("too many relocations");return;}
  size_t capacity=rel_capacity?rel_capacity*2:64;
  Rel *items=realloc(rels,capacity*sizeof *items);
  if(!items){err("out of memory recording relocation");return;}
  rels=items;rel_capacity=capacity;
 }
 char *symbol=strdup(s);if(!symbol){err("out of memory recording relocation");return;}
 rels[nr++]=(Rel){.r={.r_offset=offset,.r_info=ELF64_R_INFO(0,type),.r_addend=add},.sym=symbol,.section=section};
}
static void relocation(const char *s,uint32_t type,int64_t add){ relocation_at(s,type,add,current_section,*section_size()); }
static void record_branch(int kind,int cc,const char *symbol,int64_t addend,int short_form,size_t insn,size_t field,int field_width,uint32_t reloc_type){
 if(nbranches==sizeof branches/sizeof branches[0]){err("too many branches");return;}
 char *copy=strdup(symbol);if(!copy){err("out of memory recording branch");return;}
 branches[nbranches++]=(Branch){.line=(int)current_line,.section=current_section,.kind=kind,.cc=cc,.short_form=short_form,.insn_offset=insn,.field_offset=field,.field_width=field_width,.reloc_type=reloc_type,.symbol=copy,.addend=addend};
}
static void rex(int w,int r,int x,int b,int force){unsigned v=0x40|(w?8:0)|(r>=8?4:0)|(x>=8?2:0)|(b>=8?1:0);if(v!=0x40||force)emit(v,1);}
static void modrm_with_trailing(int reg,Op *rm,int trailing){ if(rm->kind==2||rm->kind==4){emit(0xc0|((reg&7)<<3)|(rm->reg&7),1);return;}
 if(rm->symbol&&(isdigit((unsigned char)rm->symbol[0])||
    ((rm->symbol[0]=='+'||rm->symbol[0]=='-')&&isdigit((unsigned char)rm->symbol[1])))){
   int64_t value=0;
   if(parse_integer_bits(rm->symbol,&value)!=1||add_overflow64(value,rm->disp,&value)){
     err("invalid memory displacement");return;
   }
   rm->symbol=NULL;rm->disp=value;
 }
 if(!rm->symbol&&(rm->disp<INT32_MIN||rm->disp>INT32_MAX)){err("memory displacement out of range");return;}
 int base=rm->base,idx=rm->index; int mod; int sib;
 int has_symbol=rm->symbol && rm->reloc_type!=R_X86_64_TLSDESC_CALL;
 if(rm->rip){
   /* RIP-relative addressing is ModRM mod=00, r/m=101, disp32. */
   emit(((reg&7)<<3)|5,1);
   if(rm->symbol){
     if(rm->disp<INT64_MIN+4+trailing){err("RIP-relative relocation addend out of range");return;}
     relocation(rm->symbol,rm->reloc_type?rm->reloc_type:R_X86_64_PC32,rm->disp-4-trailing);
   }
   emit(rm->symbol?0:(uint32_t)rm->disp,4);
   return;
 }
 sib=(idx>=0)||(base<0)||(base>=0&&(base&7)==4);
 if(base<0)mod=0;else if(rm->disp==0&&!rm->symbol&&!rm->disp32&&(base&7)!=5)mod=0;else if(!rm->symbol&&!rm->disp32&&rm->disp>=-128&&rm->disp<=127)mod=1;else mod=2;
 if(base>=0&&(base&7)==5&&mod==0)mod=1;
 if(rm->reloc_type==R_X86_64_TLSDESC_CALL)mod=0;
 emit((mod<<6)|((reg&7)<<3)|(sib?4:(base&7)),1);
 if(sib){int sc=rm->scale==8?3:rm->scale==4?2:rm->scale==2?1:0;emit((sc<<6)|((idx<0?4:idx&7)<<3)|(base<0?5:base&7),1);}
 if(rm->reloc_type==R_X86_64_TLSDESC_CALL){ /* Marker relocation occupies the call opcode, not a displacement. */ }
 else if(mod==1)emit((uint8_t)rm->disp,1);else if(mod==2||base<0){if(has_symbol){relocation(rm->symbol,rm->reloc_type?rm->reloc_type:(rm->addr32?R_X86_64_32:R_X86_64_32S),rm->disp);emit(0,4);}else emit((uint32_t)rm->disp,4);}
}
static void modrm(int reg,Op *rm){modrm_with_trailing(reg,rm,0);}
static void emit_xmm_mov(Op src,Op dst,int w){
 if(w!=64){err("XMM mov requires the q suffix");return;}
 if(dst.kind==4&&(src.kind==2||src.kind==3||src.kind==4)){
  if(src.kind==2&&src.width!=64){err("XMM mov requires a 64-bit general register");return;}
  emit(src.kind==2?0x66:0xf3,1);
  rex(src.kind==2,dst.reg,src.index,src.kind==3?(src.rip?-1:src.base):src.reg,0);
  emit(0x0f,1);emit(src.kind==2?0x6e:0x7e,1);modrm(dst.reg,&src);return;
 }
 if(src.kind==4&&(dst.kind==2||dst.kind==3)){
  if(dst.kind==2&&dst.width!=64){err("XMM mov requires a 64-bit general register");return;}
  emit(0x66,1);rex(dst.kind==2,src.reg,dst.index,dst.kind==2?dst.reg:(dst.rip?-1:dst.base),0);
  emit(0x0f,1);emit(dst.kind==2?0x7e:0xd6,1);modrm(src.reg,&dst);return;
 }
 err("invalid XMM mov operands");
}
static void emit_sse_binary(const char *mn,Op src,Op dst){
 if((src.kind!=4&&src.kind!=3)||dst.kind!=4){err("SSE instruction requires XMM/memory source and XMM destination");return;}
 int single=!strcmp(mn,"mulss")||!strcmp(mn,"addss")||!strcmp(mn,"subss")||!strcmp(mn,"divss")||!strcmp(mn,"cvtss2sd");
 int prefix=!strcmp(mn,"ucomiss")?0:!strcmp(mn,"ucomisd")||!strcmp(mn,"pxor")?0x66:single?0xf3:0xf2;
 int opcode=!strcmp(mn,"ucomisd")||!strcmp(mn,"ucomiss")?0x2e:
            !strcmp(mn,"mulsd")||!strcmp(mn,"mulss")?0x59:
            !strcmp(mn,"addsd")||!strcmp(mn,"addss")?0x58:
            !strcmp(mn,"subsd")||!strcmp(mn,"subss")?0x5c:
            !strcmp(mn,"divsd")||!strcmp(mn,"divss")?0x5e:
            !strcmp(mn,"cvtss2sd")||!strcmp(mn,"cvtsd2ss")?0x5a:0xef;
 if(prefix)emit(prefix,1);
 rex(0,dst.reg,src.index,src.kind==4?src.reg:(src.rip?-1:src.base),0);
 emit(0x0f,1);emit(opcode,1);modrm(dst.reg,&src);
}
static void emit_cvttsd2si(Op src,Op dst,int w){
 if((src.kind!=4&&src.kind!=3)||dst.kind!=2||(w!=32&&w!=64)||dst.width!=w){
  err("cvttsd2si requires XMM/memory source and 32- or 64-bit destination");return;
 }
 emit(0xf2,1);rex(w==64,dst.reg,src.index,src.kind==4?src.reg:(src.rip?-1:src.base),0);
 emit(0x0f,1);emit(0x2c,1);modrm(dst.reg,&src);
}
static void emit_cvtsi2sd(Op src,Op dst,int w,int single){
 if((src.kind!=2&&src.kind!=3)||dst.kind!=4||(w!=32&&w!=64)||(src.kind==2&&src.width!=w)){
  err("cvtsi2sd requires a 32- or 64-bit register/memory source and XMM destination");return;
 }
 emit(single?0xf3:0xf2,1);rex(w==64,dst.reg,src.index,src.kind==2?src.reg:(src.rip?-1:src.base),0);
 emit(0x0f,1);emit(0x2a,1);modrm(dst.reg,&src);
}
static int width_suffix(const char *mn){
 size_t n=strlen(mn); if(n<2||!strchr("bwlq",mn[n-1]))return 0;
 char b[24]; if(n>=sizeof b)return 0; memcpy(b,mn,n-1);b[n-1]=0;
 const char *known[]={"mov","movabs","add","adc","sbb","or","and","sub","xor","cmp","lea","test","xchg","inc","dec","neg","not","mul","imul","div","idiv","rol","ror","rcl","rcr","shl","sal","shr","sar","bt","bts","btr","btc","bsf","bsr","bswap","push","pop","ret","rdrand","rdseed","xadd","cmpxchg","lar","lsl","lzcnt","tzcnt","popcnt"};
 for(size_t i=0;i<sizeof known/sizeof known[0];i++)if(!strcmp(b,known[i]))return mn[n-1]=='b'?8:mn[n-1]=='w'?16:mn[n-1]=='l'?32:64;
 return 0;
}
static int sign_extended_32_literal(Op *op){
 char *end;errno=0;uintmax_t value=strtoumax(op->symbol,&end,0);
 if(op->disp||errno==ERANGE||*end||value>UINT64_MAX||
    value<UINT64_MAX-(uint64_t)INT32_MAX)return 0;
 op->disp=-1-(int64_t)(UINT64_MAX-(uint64_t)value);op->symbol=NULL;return 1;
}
static int mov_memory_immediate(Op *a,int w){
 if(a->symbol&&isdigit((unsigned char)a->symbol[0])&&
    (w!=64||!sign_extended_32_literal(a))){err("mov memory immediate out of range");return 0;}
 if(a->symbol){
   if(!expr_ident_start((unsigned char)a->symbol[0])){err("invalid symbolic mov immediate");return 0;}
   for(const char *p=a->symbol+1;*p;p++)if(!expr_ident_char((unsigned char)*p)){err("invalid symbolic mov immediate");return 0;}
   return 1;
 }
 if((w==8&&(a->disp<INT8_MIN||a->disp>UINT8_MAX))||
    (w==16&&(a->disp<INT16_MIN||a->disp>UINT16_MAX))||
    (w==32&&(a->disp<INT32_MIN||a->disp>UINT32_MAX))||
    (w==64&&(a->disp<INT32_MIN||a->disp>INT32_MAX))){
   err("mov memory immediate out of range");return 0;
 }
 return 1;
}
static int mov_memory_destination(Op *b){
 if(b->symbol&&isdigit((unsigned char)b->symbol[0])&&!sign_extended_32_literal(b)){
   err("mov memory displacement out of range");return 0;
 }
 if(b->symbol){
   if(!expr_ident_start((unsigned char)b->symbol[0])){err("invalid symbolic mov displacement");return 0;}
   for(const char *p=b->symbol+1;*p;p++)if(!expr_ident_char((unsigned char)*p)){err("invalid symbolic mov displacement");return 0;}
 }else if(b->disp<INT32_MIN||b->disp>INT32_MAX){
   err("mov memory displacement out of range");return 0;
 }
 return 1;
}
static void movlike(const char *mn,Op a,Op b,int w){ if(!w)w=b.width?b.width:a.width;if(!w)w=32;
 if((a.kind==2&&a.width!=w)||(b.kind==2&&b.width!=w)){err("mov register width does not match instruction width");return;}
 if(a.kind==1&&b.kind==3){
   if(strcmp(mn,"mov")){err("movabs does not support an immediate memory destination");return;}
   if(!mov_memory_immediate(&a,w)||!mov_memory_destination(&b))return;
   int bytes=w==8?1:w==16?2:4;
   if(w==16)emit(0x66,1);
   rex(w==64,0,b.index,b.rip?-1:b.base,0);
   emit(w==8?0xc6:0xc7,1);modrm_with_trailing(0,&b,bytes);
   if(a.symbol)relocation(a.symbol,w==8?R_X86_64_8:w==16?R_X86_64_16:w==32?R_X86_64_32:R_X86_64_32S,a.disp);
   emit(a.symbol?0:(uint64_t)a.disp,bytes);return;
 }
 if(w==16)emit(0x66,1);
 int byte=w==8,force=(byte&&((a.kind==2&&a.reg>=4)||(b.kind==2&&b.reg>=4)));
 if(a.kind==1&&b.kind==2){rex(w==64,0,0,b.reg,force);emit((byte?0xb0:0xb8)+(b.reg&7),1);if(a.symbol){relocation(a.symbol,w==64?R_X86_64_64:w==32?R_X86_64_32:w==16?R_X86_64_16:R_X86_64_8,a.disp);emit(0,w/8);}else emit(a.disp,w/8);return;}
 if(a.kind==2&&(b.kind==2||b.kind==3)){rex(w==64,a.reg,b.index<0?0:b.index,b.kind==2?b.reg:(b.rip?-1:b.base),force);emit(byte?0x88:0x89,1);modrm(a.reg,&b);return;}
 if((a.kind==2||a.kind==3)&&b.kind==2){
   /* GNU as selects relaxable GOTPCREL relocations for MOV loads.
      LEA and other instructions retain the plain GOTPCREL relocation. */
   if(a.kind==3&&a.rip&&a.reloc_type==R_X86_64_GOTPCREL)
     a.reloc_type=(w==64)?R_X86_64_REX_GOTPCRELX:R_X86_64_GOTPCRELX;
   rex(w==64,b.reg,a.index<0?0:a.index,a.kind==2?a.reg:(a.rip?-1:a.base),force);emit(byte?0x8a:0x8b,1);modrm(b.reg,&a);return;
 }
 err("unsupported mov operand combination");
}
static int op_width(Op a, Op b, int w){
 if(w)return w;
 if(b.width)return b.width;
 if(a.width)return a.width;
 return 32;
}
static void emit_unary(const char *mn, Op a, int w){
 if(a.kind!=2 && a.kind!=3){err("unary instruction requires register or memory operand");return;}
 if(a.width && a.width!=w){err("operand width does not match instruction width");return;}
 int byte=(w==8), group=-1, opcode=0;
 if(!strcmp(mn,"inc")){group=0;opcode=byte?0xfe:0xff;}
 else if(!strcmp(mn,"dec")){group=1;opcode=byte?0xfe:0xff;}
 else if(!strcmp(mn,"not")){group=2;opcode=byte?0xf6:0xf7;}
 else if(!strcmp(mn,"neg")){group=3;opcode=byte?0xf6:0xf7;}
 if(group<0)return;
 if(w==16)emit(0x66,1);
 int force=byte&&a.kind==2&&a.reg>=4;
 rex(w==64,0,a.index,a.kind==2?a.reg:(a.rip?-1:a.base),force);
 emit(opcode,1);modrm(group,&a);
}
static void emit_two(const char *mn, Op a, Op b, int w){
 w=op_width(a,b,w);
 if(!strcmp(mn,"lea")){
   if(a.kind!=3 || b.kind!=2 || b.width!=w || w==8){err("lea requires memory source and register destination");return;}
   if(w==16)emit(0x66,1);
   rex(w==64,b.reg,a.index,a.rip?-1:a.base,0);emit(0x8d,1);modrm(b.reg,&a);return;
 }
 if(!strcmp(mn,"test")){
   if(a.kind==1){
     if(b.kind!=2&&b.kind!=3){err("test immediate destination must be register or memory");return;}
     if(b.kind==2&&b.width!=w){err("test destination width mismatch");return;}
     if(a.symbol){err("symbolic test immediate is not supported");return;}
     if(w==16)emit(0x66,1);
     rex(w==64,0,b.index,b.kind==2?b.reg:(b.rip?-1:b.base),w==8&&b.kind==2&&b.reg>=4);
     int bytes=w==8?1:w==16?2:4;
     emit(w==8?0xf6:0xf7,1);modrm_with_trailing(0,&b,bytes);
     if(w==64&&(a.disp<INT32_MIN||a.disp>INT32_MAX)){err("64-bit test immediate out of range");return;}
     emit((uint64_t)a.disp,bytes);return;
   }
   if(a.kind!=2 || (b.kind!=2&&b.kind!=3)){err("test requires register/immediate source and register/memory destination");return;}
   if(a.width&&a.width!=w){err("test source width mismatch");return;}
   if(b.width&&b.width!=w){err("test destination width mismatch");return;}
   if(w==16)emit(0x66,1);
   rex(w==64,a.reg,b.index,b.kind==2?b.reg:(b.rip?-1:b.base),w==8&&(a.reg>=4||(b.kind==2&&b.reg>=4)));
   emit(w==8?0x84:0x85,1);modrm(a.reg,&b);return;
 }
 if(!strcmp(mn,"xchg")){
   if(a.kind!=2 || (b.kind!=2&&b.kind!=3)){err("xchg requires register source and register/memory destination");return;}
   if(a.width&&a.width!=w){err("xchg source width mismatch");return;}
   if(b.width&&b.width!=w){err("xchg destination width mismatch");return;}
   if(w==16)emit(0x66,1);
   rex(w==64,a.reg,b.index,b.kind==2?b.reg:(b.rip?-1:b.base),w==8&&(a.reg>=4||(b.kind==2&&b.reg>=4)));
   emit(w==8?0x86:0x87,1);modrm(a.reg,&b);return;
 }
 err("unsupported instruction");
}

static void emit_atomic(const char *mn, Op src, Op dst, int w){
 if(src.kind!=2 || (dst.kind!=2&&dst.kind!=3)){err("xadd/cmpxchg require register source and register/memory destination");return;}
 if(lock_prefix_active && dst.kind!=3){err("lock prefix requires a memory destination");return;}
 if(src.width && src.width!=w){err("atomic source width mismatch");return;}
 if(dst.width && dst.width!=w){err("atomic destination width mismatch");return;}
 if(w!=8&&w!=16&&w!=32&&w!=64){err("invalid atomic operand width");return;}
 if(w==16)emit(0x66,1);
 rex(w==64,src.reg,dst.index,dst.kind==2?dst.reg:(dst.rip?-1:dst.base),w==8&&(src.reg>=4||(dst.kind==2&&dst.reg>=4)));
 emit(0x0f,1);emit(!strcmp(mn,"xadd")?(w==8?0xc0:0xc1):(w==8?0xb0:0xb1),1);modrm(src.reg,&dst);
}
static void emit_cmpxchg_wide(Op dst, int wide){
 if(dst.kind!=3 || (dst.base<0 && !dst.rip)){err("cmpxchg8b/16b requires a memory operand");return;}
 if(lock_prefix_active==0){ /* LOCK is optional architecturally. */ }
 if(wide)rex(1,0,dst.index,dst.rip?-1:dst.base,0);
 else rex(0,0,dst.index,dst.rip?-1:dst.base,0);
 emit(0x0f,1);emit(0xc7,1);modrm(1,&dst);
}
static void emit_string(const char *mn, int w){
 int kind=-1,byteop=0;
 if(!strcmp(mn,"movs"))kind=0;
 else if(!strcmp(mn,"cmps"))kind=1;
 else if(!strcmp(mn,"stos"))kind=2;
 else if(!strcmp(mn,"lods"))kind=3;
 else if(!strcmp(mn,"scas"))kind=4;
 if(kind<0)return;
 if(rep_prefix_active && repne_prefix_active && kind!=1 && kind!=4){err("repne is only valid with cmps/scas here");return;}
 if(w==8)byteop=1;else if(w==16)emit(0x66,1);
 if(lock_prefix_active){err("lock prefix is invalid for string instructions");return;}
 if(rep_prefix_active)emit(repne_prefix_active?0xf2:0xf3,1);
 if(w==64)emit(0x48,1);
 static const uint8_t op8[]={0xa4,0xa6,0xaa,0xac,0xae};
 static const uint8_t opv[]={0xa5,0xa7,0xab,0xad,0xaf};
 emit(byteop?op8[kind]:opv[kind],1);
}

static void emit_shift(const char *mn, Op count, Op dst, int w){
 if(dst.kind!=2 && dst.kind!=3){err("shift destination must be register or memory");return;}
 if(dst.width && dst.width!=w){err("shift destination width mismatch");return;}
 int group=-1;
 if(!strcmp(mn,"rol"))group=0;
 else if(!strcmp(mn,"ror"))group=1;
 else if(!strcmp(mn,"rcl"))group=2;
 else if(!strcmp(mn,"rcr"))group=3;
 else if(!strcmp(mn,"shl")||!strcmp(mn,"sal"))group=4;
 else if(!strcmp(mn,"shr"))group=5;
 else if(!strcmp(mn,"sar"))group=7;
 if(group<0){err("unknown shift instruction");return;}
 int byte=(w==8), force=byte&&dst.kind==2&&dst.reg>=4;
 int op;
 if(count.kind==1){
   if(count.symbol){err("symbolic shift count is not supported");return;}
   if(count.disp<0||count.disp>255){err("shift count must fit in an unsigned byte");return;}
   if(w==16)emit(0x66,1);
   rex(w==64,0,dst.index,dst.kind==2?dst.reg:(dst.rip?-1:dst.base),force);
   if(count.disp==1)op=byte?0xd0:0xd1;
   else op=byte?0xc0:0xc1;
   emit(op,1);modrm(group,&dst);
   if(count.disp!=1)emit((uint8_t)count.disp,1);
   return;
 }
 if(count.kind==2 && count.reg==1 && count.width==8){
   if(w==16)emit(0x66,1);
   rex(w==64,0,dst.index,dst.kind==2?dst.reg:(dst.rip?-1:dst.base),force);
   emit(byte?0xd2:0xd3,1);modrm(group,&dst);return;
 }
 err("shift count must be an immediate or %cl");
}


static void emit_mov_extend(const char *mn, Op src, Op dst, int sw, int dw){
 if((src.kind!=2&&src.kind!=3)||dst.kind!=2){err("movzx/movsx requires register or memory source and register destination");return;}
 if(sw!=8&&sw!=16&&sw!=32){err("invalid move-extension source width");return;}
 if(dw!=16&&dw!=32&&dw!=64){err("invalid move-extension destination width");return;}
 if(dw<=sw){err("move-extension destination must be wider than source");return;}
 if(src.width&&src.width!=sw){err("move-extension source width mismatch");return;}
 if(dst.width&&dst.width!=dw){err("move-extension destination width mismatch");return;}
 if(dw==16)emit(0x66,1);
 rex(dw==64,dst.reg,src.index,src.kind==2?src.reg:(src.rip?-1:src.base),
     sw==8&&src.kind==2&&src.reg>=4);
 int sign=!strncmp(mn,"movs",4);
 if(sw==32&&dw==64&&sign){emit(0x63,1);modrm(dst.reg,&src);return;}
 emit(0x0f,1);
 emit(sw==8?(sign?0xbe:0xb6):(sign?0xbf:0xb7),1);
 modrm(dst.reg,&src);
}
static void emit_random(const char *mn, Op dst, int w){
 if(dst.kind!=2&&dst.kind!=3){err("rdrand/rdseed requires register or memory operand");return;}
 if(w!=16&&w!=32&&w!=64){err("rdrand/rdseed supports 16/32/64-bit operands");return;}
 if(dst.width&&dst.width!=w){err("rdrand/rdseed operand width mismatch");return;}
 if(w==16)emit(0x66,1);
 rex(w==64,0,dst.index,dst.kind==2?dst.reg:(dst.rip?-1:dst.base),0);
 emit(0x0f,1);emit(0xc7,1);modrm(!strcmp(mn,"rdrand")?6:7,&dst);
}

static void emit_muldiv(const char *mn, Op a, int w){
 if(a.kind!=2 && a.kind!=3){err("multiply/divide requires register or memory operand");return;}
 if(a.width && a.width!=w){err("multiply/divide operand width mismatch");return;}
 int group=!strcmp(mn,"mul")?4:!strcmp(mn,"imul")?5:!strcmp(mn,"div")?6:7;
 if(w==16)emit(0x66,1);
 rex(w==64,0,a.index,a.kind==2?a.reg:(a.rip?-1:a.base),w==8&&a.kind==2&&a.reg>=4);
 emit(w==8?0xf6:0xf7,1);modrm(group,&a);
}
static void emit_imul2(Op src, Op dst, int w){
 if((src.kind!=2&&src.kind!=3)||dst.kind!=2){err("two-operand imul requires register/memory source and register destination");return;}
 if(w==8){err("two-operand imul has no byte form");return;}
 if((src.width&&src.width!=w)||(dst.width&&dst.width!=w)){err("imul operand width mismatch");return;}
 if(w==16)emit(0x66,1);
 rex(w==64,dst.reg,src.index,src.kind==2?src.reg:(src.rip?-1:src.base),0);
 emit(0x0f,1);emit(0xaf,1);modrm(dst.reg,&src);
}
static void emit_imul3(Op imm, Op src, Op dst, int w){
 if(imm.kind!=1 || (src.kind!=2&&src.kind!=3) || dst.kind!=2){err("three-operand imul expects immediate, register/memory, register");return;}
 if(w==8){err("three-operand imul has no byte form");return;}
 if((src.width&&src.width!=w)||(dst.width&&dst.width!=w)){err("imul operand width mismatch");return;}
 if(imm.symbol){err("symbolic imul immediate is not supported");return;}
 int64_t v=imm.disp;int shortimm=v>=-128&&v<=127;
 if(w==16){if(v<INT16_MIN||v>INT16_MAX){err("imul immediate out of range");return;}emit(0x66,1);}
 else if(w==32&&(v<INT32_MIN||v>INT32_MAX)){err("imul immediate out of range");return;}
 else if(w==64&&(v<INT32_MIN||v>INT32_MAX)){err("64-bit imul immediate must fit signed 32 bits");return;}
 int bytes=shortimm?1:(w==16?2:4);
 rex(w==64,dst.reg,src.index,src.kind==2?src.reg:(src.rip?-1:src.base),0);
 emit(shortimm?0x6b:0x69,1);modrm_with_trailing(dst.reg,&src,bytes);emit((uint64_t)v,bytes);
}

static int condition_code(const char *s){
 static const struct { const char *n; int cc; } names[]={
  {"o",0},{"no",1},{"b",2},{"c",2},{"nae",2},{"ae",3},{"nb",3},{"nc",3},
  {"e",4},{"z",4},{"ne",5},{"nz",5},{"be",6},{"na",6},{"a",7},{"nbe",7},
  {"s",8},{"ns",9},{"p",10},{"pe",10},{"np",11},{"po",11},
  {"l",12},{"nge",12},{"ge",13},{"nl",13},{"le",14},{"ng",14},{"g",15},{"nle",15}
 };
 for(size_t i=0;i<sizeof names/sizeof names[0];i++)if(!strcmp(s,names[i].n))return names[i].cc;
 return -1;
}
static int parse_cc_mnemonic(const char *mn,const char *prefix,int *cc){
 size_t n=strlen(prefix);if(strncmp(mn,prefix,n))return 0;
 int c=condition_code(mn+n);if(c<0)return 0;*cc=c;return 1;
}
static void emit_bitop(const char *mn,Op index,Op dst,int w){
 if(dst.kind!=2&&dst.kind!=3){err("bit operation destination must be register or memory");return;}
 if(dst.width&&dst.width!=w){err("bit operation destination width mismatch");return;}
 int group=-1,regop=0,immop=0;
 if(!strcmp(mn,"bt")){group=4;regop=0xa3;immop=0xa;}
 else if(!strcmp(mn,"bts")){group=5;regop=0xab;immop=0xa;}
 else if(!strcmp(mn,"btr")){group=6;regop=0xb3;immop=0xa;}
 else if(!strcmp(mn,"btc")){group=7;regop=0xbb;immop=0xa;}
 if(group<0)return;
 if(w==16)emit(0x66,1);
 if(index.kind==2){
  if(index.width!=w){err("bit index register width mismatch");return;}
  rex(w==64,index.reg,dst.index,dst.kind==2?dst.reg:(dst.rip?-1:dst.base),0);
  emit(0x0f,1);emit(regop,1);modrm(index.reg,&dst);return;
 }
 if(index.kind==1){
  if(index.symbol||index.disp<0||index.disp>255){err("bit index immediate must fit unsigned byte");return;}
  rex(w==64,0,dst.index,dst.kind==2?dst.reg:(dst.rip?-1:dst.base),0);
  emit(0x0f,1);emit(0xba,1);modrm(group,&dst);emit((uint8_t)index.disp,1);return;
 }
 (void)immop;err("bit index must be register or immediate");
}
static void emit_scan(const char *mn,Op src,Op dst,int w){
 if((src.kind!=2&&src.kind!=3)||dst.kind!=2){err("bsf/bsr require register/memory source and register destination");return;}
 if(w==8){err("bsf/bsr do not have byte forms");return;}
 if((src.width&&src.width!=w)||(dst.width&&dst.width!=w)){err("bsf/bsr operand width mismatch");return;}
 if(w==16)emit(0x66,1);
 rex(w==64,dst.reg,src.index,src.kind==2?src.reg:(src.rip?-1:src.base),0);
 emit(0x0f,1);emit(!strcmp(mn,"bsf")?0xbc:0xbd,1);modrm(dst.reg,&src);
}
static void emit_bswap(Op a,int w){
 if(a.kind!=2|| (w!=32&&w!=64)){err("bswap requires a 32- or 64-bit register");return;}
 if(a.width!=w){err("bswap register width mismatch");return;}
 rex(w==64,0,0,a.reg,0);emit(0x0f,1);emit(0xc8+(a.reg&7),1);
}
static void emit_setcc(int cc,Op dst){
 if(dst.kind!=2&&dst.kind!=3){err("setcc destination must be register or memory");return;}
 if(dst.kind==2&&dst.width!=8){err("setcc requires an 8-bit register");return;}
 int force=dst.kind==2&&dst.reg>=4;
 rex(0,0,dst.index,dst.kind==2?dst.reg:(dst.rip?-1:dst.base),force);
 emit(0x0f,1);emit(0x90+cc,1);modrm(0,&dst);
}
static void emit_cmovcc(int cc,Op src,Op dst,int w){
 if((src.kind!=2&&src.kind!=3)||dst.kind!=2){err("cmovcc requires register/memory source and register destination");return;}
 if(w==8){err("cmovcc has no byte form");return;}
 if((src.width&&src.width!=w)||dst.width!=w){err("cmovcc operand width mismatch");return;}
 if(w==16)emit(0x66,1);
 rex(w==64,dst.reg,src.index,src.kind==2?src.reg:(src.rip?-1:src.base),0);
 emit(0x0f,1);emit(0x40+cc,1);modrm(dst.reg,&src);
}

static void emit_lar_lsl(const char *mn, Op src, Op dst, int w){
 if((src.kind!=2&&src.kind!=3)||dst.kind!=2){err("lar/lsl require r/m16 source and register destination");return;}
 if(src.kind==2&&src.width!=16){err("lar/lsl source register must be 16-bit");return;}
 if(w!=16&&w!=32){err("lar/lsl destination must be 16 or 32 bits in 64-bit mode");return;}
 if(dst.width!=w){err("lar/lsl destination width mismatch");return;}
 if(w==16)emit(0x66,1);
 rex(w==64,dst.reg,src.index,src.kind==2?src.reg:(src.rip?-1:src.base),0);
 emit(0x0f,1);emit(!strcmp(mn,"lar")?0x02:0x03,1);modrm(dst.reg,&src);
}
static void emit_verr_verw(const char *mn, Op src){
 if(src.kind!=2&&src.kind!=3){err("verr/verw require a 16-bit register or memory operand");return;}
 if(src.kind==2&&src.width!=16){err("verr/verw register operand must be 16-bit");return;}
 rex(0,0,src.index,src.kind==2?src.reg:(src.rip?-1:src.base),0);
 emit(0x0f,1);emit(0x00,1);modrm(!strcmp(mn,"verr")?4:5,&src);
}
static void emit_bitcount(const char *mn, Op src, Op dst, int w){
 if((src.kind!=2&&src.kind!=3)||dst.kind!=2){err("lzcnt/tzcnt/popcnt require register/memory source and register destination");return;}
 if(w!=16&&w!=32&&w!=64){err("lzcnt/tzcnt/popcnt support 16-, 32-, and 64-bit operands");return;}
 if((src.width&&src.width!=w)||dst.width!=w){err("lzcnt/tzcnt/popcnt operand width mismatch");return;}
 if(w==16)emit(0x66,1);
 emit(0xf3,1);
 rex(w==64,dst.reg,src.index,src.kind==2?src.reg:(src.rip?-1:src.base),0);
 emit(0x0f,1);
 emit(!strcmp(mn,"lzcnt")?0xbd:!strcmp(mn,"tzcnt")?0xbc:0xb8,1);
 modrm(dst.reg,&src);
}

static void emit_pushpop(const char *mn,Op a,int w){
 int push=!strcmp(mn,"push");
 if(w==32||w==8){err("push/pop support only 16- and 64-bit operands");return;}
 if(a.kind==1){
   if(!push){err("pop does not accept an immediate");return;}
   if(w==16){if(a.symbol){err("symbolic 16-bit push immediate is unsupported");return;}if(a.disp<INT16_MIN||a.disp>UINT16_MAX){err("push immediate out of range");return;}emit(0x66,1);emit(0x68,1);emit((uint64_t)a.disp,2);return;}
   if(a.symbol){emit(0x68,1);relocation(a.symbol,R_X86_64_32S,a.disp);emit(0,4);return;}
   if(a.disp<INT32_MIN||a.disp>INT32_MAX){err("pushq immediate must fit signed 32 bits");return;}
   if(a.disp>=-128&&a.disp<=127){emit(0x6a,1);emit((uint8_t)a.disp,1);}else{emit(0x68,1);emit((uint32_t)a.disp,4);}return;
 }
 if(a.kind==2){
   if(a.width!=w){err("push/pop register width mismatch");return;}
   if(w==16)emit(0x66,1);
   rex(0,0,0,a.reg,0);emit((push?0x50:0x58)+(a.reg&7),1);return;
 }
 if(a.kind==3){
   if(w==16)emit(0x66,1);
   rex(0,0,a.index,a.rip?-1:a.base,0);emit(push?0xff:0x8f,1);modrm(push?6:0,&a);return;
 }
 err("invalid push/pop operand");
}

static int split_operands(char *args, char **v, int max){
 int n=0,depth=0;char *start=args;char quote=0;
 for(char *p=args;;p++){
   if(quote){if(*p=='\\'&&p[1]){p++;continue;}if(*p==quote)quote=0;}
   else if(*p=='\''||*p=='"')quote=*p;
   else if(*p=='('||*p=='['||*p=='{')depth++;
   else if((*p==')'||*p==']'||*p=='}')&&depth>0)depth--;
   if(((*p==','&&depth==0&&!quote)||!*p)){int end=!*p;if(n>=max)return -1;if(!end)*p=0;v[n++]=trim(start);if(end)break;start=p+1;}
 }
 return n;
}
static int parse_csv(char *args,char **v,int max){ return split_operands(args,v,max); }
enum { DECL_GLOBAL, DECL_LOCAL, DECL_WEAK, DECL_EXTERN, DECL_HIDDEN, DECL_PROTECTED, DECL_INTERNAL };
static void declare_symbols(char *args,int kind){
 char *part=args;int seen=0;
 for(;;){
  char *comma=strchr(part,',');if(comma)*comma=0;
  char *name=trim(part);
  if(!*name){if(!comma&&seen)return;err("symbol declaration expects a valid symbol list");return;}
  if(!valid_symbol_name(name)){err("invalid symbol name in declaration");return;}
  seen=1;
  if(kind!=DECL_EXTERN){
   Sym *s=symget(name);if(!s)return;
   if(kind==DECL_WEAK){if(s->defined&&s->section==SHN_COMMON){err("symbol cannot be both weak and common");return;}s->bind=STB_WEAK;}
   else if(kind==DECL_GLOBAL&&s->bind!=STB_WEAK)s->bind=STB_GLOBAL;
   else if(kind==DECL_LOCAL){s->local_common=1;if(s->bind!=STB_WEAK)s->bind=STB_LOCAL;}
   else if(kind==DECL_HIDDEN)s->visibility=STV_HIDDEN;
   else if(kind==DECL_PROTECTED)s->visibility=STV_PROTECTED;
   else if(kind==DECL_INTERNAL)s->visibility=STV_INTERNAL;
  }
  if(!comma)return;
  part=comma+1;
 }
}
static size_t common_default_align(uint64_t size,int local){
 size_t a=1;
 if(local){while(a<8&&a*2<=size)a*=2;}
 else {while(a<16&&a<size)a*=2;}
 return a;
}
static void allocate_common(Sym *sym,uint64_t size,size_t align){
 if(size>NOBITS_CAP){err(".bss too large");return;}
 if(ncommon_allocations==sizeof common_allocations/sizeof common_allocations[0]){err("too many local common symbols");return;}
 if(align>base_align[3])base_align[3]=align;
 sym->defined=1;sym->section=3;sym->value=0;sym->size=size;sym->type=STT_OBJECT;sym->pending_common=1;
 common_allocations[ncommon_allocations++]=(CommonAllocation){sym,size,align,current_location};
}
static void finish_common_allocations(void){
 for(size_t i=0;i<ncommon_allocations;i++){
  CommonAllocation *a=&common_allocations[i];current_location=a->location;
  size_t pad=(a->align-nb%a->align)%a->align;
  if(nb>NOBITS_CAP||pad>NOBITS_CAP-nb||a->size>NOBITS_CAP-nb-pad){err(".bss too large");return;}
  nb+=pad;a->sym->value=nb;a->sym->pending_common=0;nb+=(size_t)a->size;
 }
}
static void warn_common_size(const Sym *sym,uint64_t size){
 if(!report_warnings||!sym->size||sym->size==size)return;
 if(current_location)fprintf(stderr,"crunch-as: %s:%zu: warning: size of '%s' is already %" PRIu64 "; not changing to %" PRIu64 "\n",current_location->filename,current_location->line,sym->name,sym->size,size);
 else fprintf(stderr,"crunch-as: warning: size of '%s' is already %" PRIu64 "; not changing to %" PRIu64 "\n",sym->name,sym->size,size);
}
static int parse_x87_stack(const char *s){
 if(!strcmp(s,"%st"))return 0;
 if(strncmp(s,"%st(",4)||s[4]<'0'||s[4]>'7'||s[5]!=')'||s[6])return -1;
 return s[4]-'0';
}
static int emit_x87(const char *mn,char *args){
 static const struct { const char *name;unsigned char byte; } fixed[]={
  {"fyl2x",0xf1},{"frndint",0xfc},{"f2xm1",0xf0},{"fld1",0xe8},{"fscale",0xfd},
  {"fchs",0xe0},{"fabs",0xe1},{"ftst",0xe4},{"fldz",0xee}
 };
 for(size_t i=0;i<sizeof fixed/sizeof fixed[0];i++)if(!strcmp(mn,fixed[i].name)){
  if(*args)err("x87 instruction takes no operands");else {emit(0xd9,1);emit(fixed[i].byte,1);}
  return 1;
 }
 static const struct { const char *name;unsigned char opcode,byte; } implicit[]={
  {"faddp",0xde,0xc1},{"fmulp",0xde,0xc9},{"fsubrp",0xde,0xe9},
  {"fdivrp",0xde,0xf9},{"fucomip",0xdf,0xe9}
 };
 for(size_t i=0;i<sizeof implicit/sizeof implicit[0];i++)if(!strcmp(mn,implicit[i].name)){
  if(*args)err("x87 instruction operands are not supported");
  else {emit(implicit[i].opcode,1);emit(implicit[i].byte,1);}
  return 1;
 }
 static const struct { const char *name;unsigned char opcode,extension; } memory[]={
  {"fldl",0xdd,0},{"fstpl",0xdd,3},{"flds",0xd9,0},{"fstps",0xd9,3},
  {"fldt",0xdb,5},{"fstpt",0xdb,7},{"fildl",0xdb,0},{"fildll",0xdf,5},
  {"fistpl",0xdb,3},{"fistpll",0xdf,7},{"fnstcw",0xd9,7},{"fldcw",0xd9,5}
 };
 for(size_t i=0;i<sizeof memory/sizeof memory[0];i++)if(!strcmp(mn,memory[i].name)){
  Op a;if(!parseop(args,&a)||a.kind!=3){err("x87 load/store requires a memory operand");return 1;}
  rex(0,0,a.index,a.rip?-1:a.base,0);emit(memory[i].opcode,1);modrm(memory[i].extension,&a);return 1;
 }
 if(!strcmp(mn,"fld")||!strcmp(mn,"fxch")||!strcmp(mn,"fstp")){
  int reg=parse_x87_stack(trim(args));if(reg<0){err("invalid x87 stack register");return 1;}
  emit(!strcmp(mn,"fstp")?0xdd:0xd9,1);
  emit((!strcmp(mn,"fld")?0xc0:!strcmp(mn,"fxch")?0xc8:0xd8)+reg,1);return 1;
 }
 if(!strcmp(mn,"fsub")){
  char *v[2];int n=split_operands(args,v,2);int reg=n==2?parse_x87_stack(v[0]):-1;
  if(reg<0||parse_x87_stack(v[1])!=0){err("fsub requires %st(n), %st");return 1;}
  emit(0xd8,1);emit(0xe0+reg,1);return 1;
 }
 return 0;
}
static int parse_special_reg(const char *s, int *kind, int *number_out){
 static const char *seg[] = {"%es","%cs","%ss","%ds","%fs","%gs"};
 for(int i=0;i<6;i++) if(!strcmp(s,seg[i])){*kind=1;*number_out=i;return 1;}
 if((s[0]=='%' && (s[1]=='c'||s[1]=='d') && s[2]=='r')){
   char *end=NULL; long n=strtol(s+3,&end,10);
   if(end && *end==0 && n>=0 && n<=(s[1]=='c'?8:7)){
     *kind=s[1]=='c'?2:3;*number_out=(int)n;return 1;
   }
 }
 return 0;
}
/* Returns 1 when this was a special-register MOV (including errors), 0 otherwise. */
static int emit_special_mov(char *args){
 char *copy=strdup(args); if(!copy){err("out of memory");return 1;}
 char *v[2]; int n=split_operands(copy,v,2); if(n!=2){free(copy);return 0;}
 int sk=0,sn=0,dk=0,dn=0;
 int hs=parse_special_reg(v[0],&sk,&sn), hd=parse_special_reg(v[1],&dk,&dn);
 if(!hs&&!hd){free(copy);return 0;}
 Op a,b;
 if(hs&&hd){err("MOV between two special registers is invalid");free(copy);return 1;}
 if(!hs&&!parseop(v[0],&a)){err("invalid MOV source");free(copy);return 1;}
 if(!hd&&!parseop(v[1],&b)){err("invalid MOV destination");free(copy);return 1;}
 if(hs){
   if(sk==1){
     if(b.kind!=2&&b.kind!=3){err("segment-register MOV destination must be register or memory");free(copy);return 1;}
     if(b.kind==2 && b.width!=16 && b.width!=32 && b.width!=64){err("invalid segment-register MOV destination width");free(copy);return 1;}
     if(b.kind==2 && b.width==16)emit(0x66,1);
     rex(0,sn,b.kind==3?b.index:-1,b.kind==2?b.reg:(b.rip?-1:b.base),0);
     emit(0x8c,1);modrm(sn,&b);free(copy);return 1;
   }
   if((sk==2||sk==3) && b.kind==2 && b.width==64){
     rex(0,sn,0,b.reg,0);emit(0x0f,1);emit(sk==2?0x20:0x21,1);modrm(sn,&b);free(copy);return 1;
   }
   err("control/debug register MOV requires a 64-bit general register");free(copy);return 1;
 }
 if(dk==1){
   if(dn==1){err("MOV cannot load CS");free(copy);return 1;}
   if(a.kind!=2&&a.kind!=3){err("segment-register MOV source must be register or memory");free(copy);return 1;}
   if(a.kind==2 && a.width!=16 && a.width!=32 && a.width!=64){err("invalid segment-register MOV source width");free(copy);return 1;}
   rex(0,dn,a.kind==3?a.index:-1,a.kind==2?a.reg:(a.rip?-1:a.base),0);
   emit(0x8e,1);modrm(dn,&a);free(copy);return 1;
 }
 if((dk==2||dk==3) && a.kind==2 && a.width==64){
   rex(0,dn,0,a.reg,0);emit(0x0f,1);emit(dk==2?0x22:0x23,1);modrm(dn,&a);free(copy);return 1;
 }
 err("control/debug register MOV requires a 64-bit general register");free(copy);return 1;
}
static int parse_symbol_difference(const char *src, char **left, char **right, int64_t *addend){
 char *c=strdup(src); if(!c){err("out of memory parsing symbol difference");return -1;} char *p=trim(c); char *a=p;
 if(!(isalpha((unsigned char)*p)||*p=='_'||*p=='.'||*p=='$')){free(c);return 0;}
 while(isalnum((unsigned char)*p)||*p=='_'||*p=='.'||*p=='$')p++;
 char save=*p; *p=0; char *ln=strdup(a); *p=save; if(!ln){free(c);err("out of memory parsing symbol difference");return -1;} p=trim(p);
 if(*p!='-'){free(ln);free(c);return 0;} p++;p=trim(p);
 char *b=p;if(!(isalpha((unsigned char)*p)||*p=='_'||*p=='.'||*p=='$')){free(ln);free(c);return 0;}
 while(isalnum((unsigned char)*p)||*p=='_'||*p=='.'||*p=='$')p++;
 char save2=*p;*p=0;char *rn=strdup(b);*p=save2;if(!rn){free(ln);free(c);err("out of memory parsing symbol difference");return -1;}p=trim(p);int64_t add=0;
 if(*p){char sign=*p++;if((sign!='+'&&sign!='-')||!signed_addend(sign,trim(p),&add)){free(ln);free(rn);free(c);return 0;}}
 *left=ln;*right=rn;*addend=add;free(c);return 1;
}
static int emit_tls_relocation(char *arg,int bytes){
 char *at=strrchr(arg,'@'); if(!at)return 0;
 const char *kind=at+1; uint32_t type=0;
 if(!strcmp(kind,"TPOFF")) type=bytes==8?R_X86_64_TPOFF64:bytes==4?R_X86_64_TPOFF32:0;
 else if(!strcmp(kind,"DTPOFF")) type=bytes==8?R_X86_64_DTPOFF64:bytes==4?R_X86_64_DTPOFF32:0;
 else if(!strcmp(kind,"DTPMOD")) type=bytes==8?R_X86_64_DTPMOD64:0;
 else {err("unsupported relocation modifier in data directive");return 1;}
 if(!type){err("invalid width for TLS relocation modifier");return 1;}
 *at=0;const char *name=NULL;int64_t add=0;
 if(!symbol_expr(arg,&name,&add)||(type==R_X86_64_DTPMOD64&&add)){err("invalid TLS relocation expression");return 1;}
 relocation(name,type,add); emit(0,bytes); return 1;
}
static void emit_data_value(char *arg,int bytes){
 if(emit_tls_relocation(arg,bytes))return;
 char *left=NULL,*right=NULL;int64_t add=0;
 int difference=parse_symbol_difference(arg,&left,&right,&add);
 if(difference<0)return;
 if(difference){
   if(bytes!=4&&bytes!=8){err("symbol differences require .long or .quad");free(left);free(right);return;}
   Sym *ls=find_symbol(left),*rs=find_symbol(right);
   /* An absolute symbol is a constant, not a section-relative term. Fold it
      into the relocation addend instead of creating a difference fixup. */
   if(ls&&ls->defined&&ls->section==SHN_ABS && rs&&rs->defined&&rs->section==SHN_ABS){
     int64_t lv=(int64_t)ls->value,rv=(int64_t)rs->value;
     if((rv>0&&lv<INT64_MIN+rv)||(rv<0&&lv>INT64_MAX+rv)){err("absolute expression overflow");free(left);free(right);return;}
     int64_t value=lv-rv;
     if((add>0&&value>INT64_MAX-add)||(add<0&&value<INT64_MIN-add)){err("absolute expression overflow");free(left);free(right);return;}
     emit((uint64_t)(value+add),bytes);free(left);free(right);return;
   }
   if(rs&&rs->defined&&rs->section==SHN_ABS && (!ls || ls->section!=SHN_ABS)){
     int64_t rv=(int64_t)rs->value;
     if((rv>0&&add<INT64_MIN+rv)||(rv<0&&add>INT64_MAX+rv)){err("relocation addend overflow");free(left);free(right);return;}
     add-=rv;
     relocation(left,bytes==8?R_X86_64_64:R_X86_64_32,add);
     emit(0,bytes);free(left);free(right);return;
   }
   if(ls&&ls->defined&&ls->section==SHN_ABS){
     err("cannot represent an absolute-symbol-minus-relocatable-symbol expression");free(left);free(right);return;
   }
   if(section_is_nobits(current_section)){err("symbol differences in NOBITS sections are unsupported");free(left);free(right);return;}
   if(ndiffs==4096){err("too many symbol-difference fixups");free(left);free(right);return;}
   size_t off=*section_size();emit(0,bytes);
   diffs[ndiffs++]=(DiffFixup){.section=current_section,.width=bytes,.offset=off,.left=left,.right=right,.addend=add,.location=current_location};return;
 }
 int64_t value=0;
 if(resolve_absolute_expr(arg,&value)){emit((uint64_t)value,bytes);return;}
 int numeric=parse_integer_bits(arg,&value);
 if(numeric<0){err("invalid or out-of-range data integer");return;}
 if(numeric>0){emit((uint64_t)value,bytes);return;}
 Op o; if(!parseop(arg,&o)){err("invalid data expression");return;}
 if(o.kind==1 || o.symbol){
   const char *sym=o.symbol;
   if(!sym){ emit((uint64_t)o.disp,bytes); return; }
   if(bytes==8)relocation(sym,R_X86_64_64,o.disp);
   else if(bytes==4)relocation(sym,R_X86_64_32,o.disp);
   else {err("symbol relocations are supported only for .long and .quad");return;}
   emit(0,bytes);
 } else emit((uint64_t)o.disp,bytes);
}
static unsigned char string_character(char **cursor){
 unsigned char c=(unsigned char)*(*cursor)++;
 if(c!='\\')return c;
 if(!**cursor){err("unterminated string escape");return 0;}
 c=(unsigned char)*(*cursor)++;
 if(c=='x'||c=='X'){
  unsigned value=0;
  for(;;){
   unsigned char d=(unsigned char)**cursor;unsigned digit;
   if(d>='0'&&d<='9')digit=d-'0';
   else if(d>='a'&&d<='f')digit=d-'a'+10;
   else if(d>='A'&&d<='F')digit=d-'A'+10;
   else break;
   value=(value*16+digit)&255;(*cursor)++;
  }
  return (unsigned char)value;
 }
 if(c>='0'&&c<='9'){
  unsigned value=c-'0';
  for(int i=1;i<3&&**cursor>='0'&&**cursor<='9';i++)value=value*8+(unsigned)*(*cursor)++-'0';
  return (unsigned char)(value&255);
 }
 if(c=='b')return '\b';
 if(c=='f')return '\f';
 if(c=='n')return '\n';
 if(c=='r')return '\r';
 if(c=='t')return '\t';
 if(c=='v')return '\v';
 return c;
}
static void file_directive(char *p){
 p=trim(p);
 if(*p!='"'){
  err(isdigit((unsigned char)*p)?"numbered .file directives require unsupported DWARF line tables":".file expects a quoted filename");
  return;
 }
 p++;
 char *name=malloc(strlen(p)+1);
 if(!name){err("out of memory recording .file");return;}
 size_t n=0;
 while(*p&&*p!='"'&&!failed)name[n++]=(char)string_character(&p);
 if(failed){free(name);return;}
 if(*p!='"'){free(name);err("unterminated .file filename");return;}
 if(*trim(p+1)){free(name);err("unexpected text after .file filename");return;}
 name[n]=0;
 if(nfile_symbols>=UINT32_MAX-1){free(name);err("too many .file symbols");return;}
 if(nfile_symbols==file_symbol_capacity){
  if(file_symbol_capacity>SIZE_MAX/2/sizeof *file_symbols){free(name);err("too many .file symbols");return;}
  size_t capacity=file_symbol_capacity?file_symbol_capacity*2:8;
  char **items=realloc(file_symbols,capacity*sizeof *items);
  if(!items){free(name);err("out of memory recording .file");return;}
  file_symbols=items;file_symbol_capacity=capacity;
 }
 file_symbols[nfile_symbols++]=name;
}
static void emit_string_directive(char *p,int zero){
 int group=0;
 for(;;){
  while(isspace((unsigned char)*p))p++;
  if(!*p||*p==','){
   if(group&&zero){emit(0,1);if(failed)return;}
   group=0;if(!*p)return;p++;continue;
  }
  if(*p!='"'){err("unexpected text in string directive");return;}
  group=1;p++;
  while(*p&&*p!='"'){
   unsigned char c=string_character(&p);if(failed)return;
   emit(c,1);if(failed)return;
  }
  if(*p!='"'){err("unterminated string");return;}
  p++;
 }
}
static int select_tls_section(int nobits){
 const char *name=nobits?".tbss":".tdata"; int id=-1;
 for(size_t i=0;i<ncustom_sections;i++)if(!custom_sections[i].group&&!strcmp(custom_sections[i].name,name)){id=5+(int)i;break;}
 if(id<0){if(ncustom_sections==MAX_CUSTOM_SECTIONS){err("too many custom sections");return 0;}id=5+(int)ncustom_sections++;CustomSection *cs=&custom_sections[id-5];memset(cs,0,sizeof *cs);strcpy(cs->name,name);cs->flags=SHF_ALLOC|SHF_WRITE|SHF_TLS;cs->type=nobits?SHT_NOBITS:SHT_PROGBITS;cs->align=1;}
 current_section=id;return 1;
}
static int validate_subsection(char *operand){
 operand=trim(operand);
 if(!*operand)return 1;
 int64_t value=0;
 if(!resolve_absolute_expr(operand,&value)){err("section subsection must be an absolute expression");return 0;}
 if(value!=0){err("nonzero section subsections are unsupported");return 0;}
 return 1;
}
static int directive_is(const char *line,const char *d);
static void directive(char *line);
static void directive(char *line){
 if(directive_is(line,".file")){file_directive(line+5);return;}
 if(directive_is(line,".text")){if(validate_subsection(line+5))current_section=1;return;}
 if(directive_is(line,".data")){if(validate_subsection(line+5))current_section=2;return;}
 if(directive_is(line,".bss")){if(validate_subsection(line+4))current_section=3;return;}
 if(directive_is(line,".rodata")){if(validate_subsection(line+7))current_section=4;return;}
 if(directive_is(line,".tdata")){if(validate_subsection(line+6))select_tls_section(0);return;}
 if(directive_is(line,".tbss")){if(validate_subsection(line+5))select_tls_section(1);return;}
 if(!strncmp(line,".pushsection",12)&&isspace((unsigned char)line[12])){
   if(section_stack_depth==MAX_SECTION_STACK){err("section stack overflow");return;}
   section_stack[section_stack_depth]=current_section;
   section_stack_locations[section_stack_depth++]=current_location;
   char *rest=trim(line+12); size_t z=strlen(rest); char *tmp=malloc(z+10); if(!tmp){err("out of memory");return;} snprintf(tmp,z+10,".section %s",rest); directive(tmp); free(tmp); return;
 }
 if(!strcmp(line,".popsection")){if(!section_stack_depth){err(".popsection without matching .pushsection");return;}current_section=section_stack[--section_stack_depth];return;}
 if(!strncmp(line,".section",8) && isspace((unsigned char)line[8])){
   char *v[6];int n=parse_csv(trim(line+8),v,6);char *name=n>0?trim(v[0]):NULL;
   if(n<0){err("unsupported extra .section attributes");return;}
   if(!name||!*name){err(".section expects a section name");return;}
   int base=!strcmp(name,".text")?1:!strcmp(name,".data")?2:!strcmp(name,".bss")?3:!strcmp(name,".rodata")?4:0;
   int id=base?base:-1;
   if(n==1){
    if(!base)for(size_t i=0;i<ncustom_sections;i++)if(!custom_sections[i].group&&!strcmp(custom_sections[i].name,name)){id=5+(int)i;break;}
    if(id<0){err("custom .section requires quoted flags on first declaration");return;}current_section=id;return;
   }
   if(v[1][0]!='"'){err(".section requires quoted flags");return;}
   char *q=strchr(v[1]+1,'"');if(!q){err("unterminated .section flags");return;}
   if(*trim(q+1)){err("invalid text after .section flags");return;}*q=0;
   uint64_t flags=0;for(char *f=v[1]+1;*f;f++){if(*f=='a')flags|=SHF_ALLOC;else if(*f=='w')flags|=SHF_WRITE;else if(*f=='x')flags|=SHF_EXECINSTR;else if(*f=='M')flags|=SHF_MERGE;else if(*f=='S')flags|=SHF_STRINGS;else if(*f=='T')flags|=SHF_TLS;else if(*f=='G')flags|=SHF_GROUP;else if(*f=='R')flags|=SHF_GNU_RETAIN;else {err("unsupported section flag");return;}}
   uint32_t type=base?section_type(base):SHT_PROGBITS;
   if(n<3&&!strcmp(name,".note.gnu.property"))type=SHT_NOTE;
   if(n<3&&!strncmp(name,".init_array",11)&&(!name[11]||name[11]=='.'))type=SHT_INIT_ARRAY;
   if(n<3&&!strncmp(name,".fini_array",11)&&(!name[11]||name[11]=='.'))type=SHT_FINI_ARRAY;
   if(n>=3){char *t=trim(v[2]);if(!strcmp(t,"@progbits")||!strcmp(t,"%progbits"))type=SHT_PROGBITS;else if(!strcmp(t,"@nobits")||!strcmp(t,"%nobits"))type=SHT_NOBITS;else if(!strcmp(t,"@note")||!strcmp(t,"%note"))type=SHT_NOTE;else if(!strcmp(t,"@init_array")||!strcmp(t,"%init_array"))type=SHT_INIT_ARRAY;else if(!strcmp(t,"@fini_array")||!strcmp(t,"%fini_array"))type=SHT_FINI_ARRAY;else {err("unsupported custom section type");return;}}
   size_t entsize=type==SHT_INIT_ARRAY||type==SHT_FINI_ARRAY?8:0;
   int attr=n>=3?3:2;
   if(flags&SHF_MERGE){
    int64_t value=0;
    if(n<=attr||!resolve_absolute_expr(v[attr++],&value)||value<=0||value>SEC_CAP){err("mergeable .section requires a positive entry size up to 1 MiB");return;}
    entsize=(size_t)value;
   }
   int group=0,comdat=0;
   const char *signature=NULL;
   if(flags&SHF_GROUP){
    if(n<=attr||!valid_symbol_name(v[attr])){err("grouped .section requires a valid signature symbol");return;}
    signature=v[attr++];
    if(n>attr){if(strcmp(v[attr++],"comdat")){err("unsupported section group linkage");return;}comdat=1;}
    for(size_t i=0;i<nsection_groups;i++)if(!strcmp(section_groups[i].signature,signature)){group=(int)i+1;break;}
    if(group&&section_groups[group-1].comdat!=comdat){err("inconsistent COMDAT attributes for section group");return;}
   }
   if(n!=attr){err("unexpected .section attributes");return;}
   if(base){if(flags!=section_flags(base)||type!=section_type(base)||entsize){err("unsupported attributes for built-in section");return;}current_section=id;return;}
   if(signature&&!group){
    if(nsection_groups==MAX_CUSTOM_SECTIONS){err("too many section groups");return;}
    char *copy=strdup(signature);if(!copy){err("out of memory recording section group");return;}
    if(!symget(signature)){free(copy);return;}
    group=(int)++nsection_groups;section_groups[group-1]=(SectionGroup){copy,comdat};
   }
   for(size_t i=0;i<ncustom_sections;i++)if(custom_sections[i].group==group&&!strcmp(custom_sections[i].name,name)){id=5+(int)i;break;}
   if(id<0){if(ncustom_sections==MAX_CUSTOM_SECTIONS){err("too many custom sections");return;}if(strlen(name)>=sizeof custom_sections[0].name){err("custom section name too long");return;}id=5+(int)ncustom_sections++;CustomSection *cs=&custom_sections[id-5];memset(cs,0,sizeof *cs);strcpy(cs->name,name);cs->flags=flags;cs->type=type;cs->align=1;cs->entsize=entsize;cs->group=group;cs->location=current_location;}
   else {CustomSection *cs=&custom_sections[id-5];if(cs->flags!=flags||cs->type!=type||cs->entsize!=entsize){err("section flags, type or entry size changed on redeclaration");return;}}
   current_section=id;return;
 }
 if((!strncmp(line,".globl",6)&&isspace((unsigned char)line[6]))||
    (!strncmp(line,".global",7)&&isspace((unsigned char)line[7]))){
   declare_symbols(line+(!strncmp(line,".global",7)?7:6),DECL_GLOBAL);return;
 }
 if(!strncmp(line,".weak",5)&&isspace((unsigned char)line[5])){
   declare_symbols(line+5,DECL_WEAK);return;
 }
 if((!strncmp(line,".hidden",7)&&isspace((unsigned char)line[7]))||(!strncmp(line,".protected",10)&&isspace((unsigned char)line[10]))||(!strncmp(line,".internal",9)&&isspace((unsigned char)line[9]))){
   int vis=line[1]=='h'?STV_HIDDEN:line[1]=='p'?STV_PROTECTED:STV_INTERNAL;
   declare_symbols(line+(vis==STV_HIDDEN?7:vis==STV_PROTECTED?10:9),
                   vis==STV_HIDDEN?DECL_HIDDEN:vis==STV_PROTECTED?DECL_PROTECTED:DECL_INTERNAL);return;
 }
 if(!strncmp(line,".symver",7)&&isspace((unsigned char)line[7])){
   char *v[2];int n=parse_csv(trim(line+7),v,2);if(n!=2||!valid_symbol_name(v[0])||!valid_symver_alias(v[1])){err(".symver expects a valid source and versioned alias");return;}
   if(nsymvers==sizeof symvers/sizeof symvers[0]){err("too many .symver directives");return;}
   for(size_t i=0;i<nsymvers;i++)if(!strcmp(symvers[i].source,v[0])&&!strcmp(symvers[i].alias,v[1]))return;
   symvers[nsymvers++]=(Symver){.source=strdup(v[0]),.alias=strdup(v[1]),.location=current_location};
   if(!symvers[nsymvers-1].source||!symvers[nsymvers-1].alias) err("out of memory in .symver");
   return;
 }
 if(!strncmp(line,".extern",7)&&isspace((unsigned char)line[7])){declare_symbols(line+7,DECL_EXTERN);return;}
 if(!strncmp(line,".local",6)&&isspace((unsigned char)line[6])){declare_symbols(line+6,DECL_LOCAL);return;}
 if((!strncmp(line,".equ",4)&&isspace((unsigned char)line[4]))||(!strncmp(line,".set",4)&&isspace((unsigned char)line[4]))){
   int is_set=line[1]=='s'; char *v[2];int n=parse_csv(trim(line+4),v,2);
   if(n!=2||!valid_symbol_name(v[0])){err(is_set?".set expects symbol,expression":".equ expects symbol,expression");return;}
   int64_t value=0;int section=SHN_ABS;uint64_t resolved,base_size=0;unsigned char base_type=STT_NOTYPE;
   if(resolve_absolute_expr(v[1],&value))resolved=(uint64_t)value;
   else {
    const char *name=NULL;int64_t add=0;Sym *base=NULL;
    if(symbol_expr(v[1],&name,&add))base=find_symbol(name);
    if(!base||!base->defined||base->section==SHN_ABS||base->section==SHN_COMMON||base->pending_common){err(".set requires an already-resolved absolute or section-relative expression");return;}
    if(add>=0){if(base->value>UINT64_MAX-(uint64_t)add){err(".set symbol offset out of range");return;}resolved=base->value+(uint64_t)add;}
    else {uint64_t magnitude=(uint64_t)(-(add+1))+1;if(base->value<magnitude){err(".set symbol offset out of range");return;}resolved=base->value-magnitude;}
    section=base->section;base_size=base->size;base_type=base->type;
   }
   Sym *sym=symget(v[0]);if(!sym)return;
   if(sym->pending_common){err("redefining a local common symbol is unsupported");return;}
   sym->defined=1;sym->section=section;sym->value=resolved;
   if(section==SHN_ABS)sym->size=0;
   else {if(!sym->size)sym->size=base_size;if(sym->type==STT_NOTYPE)sym->type=base_type;}
   return;
 }
 if(!strncmp(line,".comm",5)&&isspace((unsigned char)line[5])){
   char *v[3];int n=parse_csv(trim(line+5),v,3);if(n<2||n>3||!valid_symbol_name(v[0])){err(".comm expects symbol,size[,alignment]");return;}
   int64_t z=0,a=0;
   if(!resolve_absolute_expr(v[1],&z)||(n==3&&!resolve_absolute_expr(v[2],&a))||z<0||a<0||(a&&(a&(a-1)))||a>SEC_CAP){err("invalid .comm size or alignment");return;}
   Sym *sym=symget(v[0]);if(!sym)return;
   if(sym->defined&&sym->section!=SHN_COMMON){err(".comm symbol already defined");return;}
   if(sym->defined&&sym->local_common){err("converting a common symbol to local storage is unsupported");return;}
   if(sym->defined){warn_common_size(sym,(uint64_t)z);if(sym->size)z=(int64_t)sym->size;}
   if(sym->local_common){
    if(sym->bind!=STB_WEAK)sym->bind=STB_LOCAL;
    allocate_common(sym,(uint64_t)z,a?(size_t)a:1);return;
   }
   if(sym->bind==STB_WEAK){err("symbol cannot be both weak and common");return;}
   sym->defined=1;sym->section=SHN_COMMON;sym->value=a?(uint64_t)a:common_default_align((uint64_t)z,0);sym->size=(uint64_t)z;sym->bind=STB_GLOBAL;sym->type=STT_OBJECT;return;
 }
 if(!strncmp(line,".lcomm",6)&&isspace((unsigned char)line[6])){
   char *v[3];int n=parse_csv(trim(line+6),v,3);if(n<2||n>3||!valid_symbol_name(v[0])){err(".lcomm expects symbol,size[,alignment]");return;}
   int64_t z=0,a=1;if(!resolve_absolute_expr(v[1],&z)||z<0||z>NOBITS_CAP){err("invalid .lcomm size");return;}
   if(n==3){if(!resolve_absolute_expr(v[2],&a)||a<1||(a&(a-1))||a>SEC_CAP){err("invalid .lcomm alignment");return;}}
   else a=(int64_t)common_default_align((uint64_t)z,1);
   Sym *sym=symget(v[0]);if(!sym)return;
   if(sym->defined){err(sym->section==SHN_COMMON?"converting a common symbol to local storage is unsupported":".lcomm symbol already defined");return;}
   allocate_common(sym,(uint64_t)z,(size_t)a);return;
 }
 if(!strncmp(line,".type",5)&&isspace((unsigned char)line[5])){
   char *v[2];int n=parse_csv(trim(line+5),v,2);if(n!=2||!valid_symbol_name(v[0])){err(".type expects symbol,type");return;}Sym *s=symget(v[0]);if(!s)return;
   char *t=trim(v[1]);if(*t=='@')t++;if(!strcmp(t,"function"))s->type=STT_FUNC;else if(!strcmp(t,"object"))s->type=STT_OBJECT;else if(!strcmp(t,"tls_object"))s->type=STT_TLS;else if(!strcmp(t,"notype"))s->type=STT_NOTYPE;else err("unsupported .type value");return;
 }
 if(!strncmp(line,".size",5)&&isspace((unsigned char)line[5])){
   char *v[2];int n=parse_csv(trim(line+5),v,2);if(n!=2||!valid_symbol_name(v[0])){err(".size expects symbol,expression");return;}Sym *s=symget(v[0]);if(!s)return;
   char *e=trim(v[1]);int64_t z=0;if(resolve_absolute_expr(e,&z)&&z>=0){s->size=(uint64_t)z;return;}
   if(!strncmp(e,".-",2)){Sym *start=symget(e+2);if(start&&start->defined&&!start->pending_common&&start->section==current_section){uint64_t now=section_offset();s->size=now-start->value;return;}}
   err("unsupported .size expression");return;
 }
 if(directive_is(line,".byte")||directive_is(line,".word")||directive_is(line,".short")||directive_is(line,".long")||directive_is(line,".int")||directive_is(line,".quad")){
   char *p=line;int bytes=0;if(directive_is(p,".byte"))bytes=1;else if(directive_is(p,".word")||directive_is(p,".short"))bytes=2;else if(directive_is(p,".long")||directive_is(p,".int"))bytes=4;else bytes=8;
   while(*p&&!isspace((unsigned char)*p))p++;
   char *v[128];int n=parse_csv(trim(p),v,128);if(n<1){err("data directive requires values");return;}for(int i=0;i<n;i++)emit_data_value(v[i],bytes);return;
 }
 if(directive_is(line,".ascii")||directive_is(line,".asciz")||directive_is(line,".string")){
   int string=directive_is(line,".string");
   emit_string_directive(line+(string?7:6),string||line[5]=='z');return;
 }
 if(directive_is(line,".zero")||directive_is(line,".space")){
   char *p=line;while(*p&&!isspace((unsigned char)*p))p++;p=trim(p);char *v[2];int n=parse_csv(p,v,2);int64_t count=0,fill=0;
   size_t cap=section_is_nobits(current_section)?NOBITS_CAP:SEC_CAP;
   if(n<1||n>2||!resolve_absolute_expr(v[0],&count)||count<0||(uint64_t)count>cap||(n==2&&(!resolve_absolute_expr(v[1],&fill)||fill<0||fill>255))){err("invalid .zero/.space size or fill");return;}
   if(section_is_nobits(current_section)){if(n==2&&fill){err("nonzero fill is invalid in NOBITS section");return;}size_t *sz=section_size();if(*sz>cap||(size_t)count>cap-*sz){err("NOBITS section too large");return;}*sz+=(size_t)count;}else for(int64_t i=0;i<count;i++)emit((uint64_t)fill,1);return;
 }
 if(directive_is(line,".align")||directive_is(line,".balign")||directive_is(line,".p2align")){
   int pow=line[1]=='p';char *p=line;while(*p&&!isspace((unsigned char)*p))p++;p=trim(p);char *v[3];int n=parse_csv(p,v,3);int64_t a=0,fill=0,maxskip=-1;
   int explicit_fill=n>=2&&(n==2||*v[1]);
   if(n<1||n>3||!resolve_absolute_expr(v[0],&a)||a<0||(pow?a>20:a>SEC_CAP)||
      (explicit_fill&&*v[1]&&(!resolve_absolute_expr(v[1],&fill)||fill<0||fill>255))||
      (n==3&&*v[2]&&(!resolve_absolute_expr(v[2],&maxskip)||maxskip<0))){err("invalid alignment arguments");return;}
   size_t align=pow?((size_t)1<<(unsigned)a):(a?(size_t)a:1);
   if(align&(align-1)){err("alignment must be a power of two");return;}
   size_t *required=section_alignment(current_section);if(align>*required)*required=align;
   size_t *sz=section_size();size_t pad=(align-(*sz%align))%align;if(maxskip>0&&pad>(uint64_t)maxskip)pad=0;
   size_t cap=section_is_nobits(current_section)?NOBITS_CAP:SEC_CAP;
   if(*sz>cap||pad>cap-*sz){err("section too large");return;}
   if(section_is_nobits(current_section)){if(fill){err("nonzero fill is invalid in NOBITS section");return;}*sz+=pad;}
   else {
    if(!explicit_fill&&(section_flags(current_section)&SHF_EXECINSTR))fill=0x90;
    while(pad--)emit((uint64_t)fill,1);
   }
   return;
 }
 err("unsupported directive");
}
/* Rewrite GNU numeric local labels (1:, 1f, 1b) into unique local symbols.
 * The source is preprocessed once, so both layout/relaxation passes see identical names. */
static int append_numeric_name(char **dst,size_t *used,size_t *cap,const char *prefix,int digit,size_t line,size_t remaining){
 char name[128];int n=snprintf(name,sizeof name,"%s%d_%zu",prefix,digit,line);
 if(n<0||(size_t)n>=sizeof name||(size_t)n>SIZE_MAX-*used-1||
    remaining>SIZE_MAX-*used-(size_t)n-1)return 0;
 size_t needed=*used+(size_t)n+remaining+1;
 if(needed>*cap){
  size_t next=*cap;
  while(next<needed){if(next>SIZE_MAX/2){next=needed;break;}next*=2;}
  char *grown=realloc(*dst,next);if(!grown)return 0;*dst=grown;*cap=next;
 }
 memcpy(*dst+*used,name,(size_t)n);*used+=(size_t)n;return 1;
}
static int normalize_numeric_labels(SourceLine *lines,size_t count){
 char prefix[48];
 for(size_t salt=0;;salt++){
  snprintf(prefix,sizeof prefix,".Lcrunch_as_num_%zu_",salt);
  int found=0;for(size_t i=0;i<count;i++)if(strstr(lines[i].text,prefix)){found=1;break;}
  if(!found)break;
  if(salt==SIZE_MAX){err("cannot allocate unique numeric label names");return 0;}
 }
 unsigned char *defs[10];
 for(int d=0;d<10;d++){defs[d]=calloc(count?count:1,1);if(!defs[d]){err("out of memory normalizing numeric labels");for(int j=0;j<d;j++)free(defs[j]);return 0;}}
 for(size_t i=0;i<count;i++){
  char *p=trim(lines[i].text);
  if(isdigit((unsigned char)p[0])&&p[1]==':')defs[p[0]-'0'][i]=1;
 }
 for(size_t i=0;i<count;i++){
  current_location=lines[i].location;
  const char *src=lines[i].text;size_t length=strlen(src),cap=length+1,used=0;char *dst=malloc(cap);
  if(!dst){err("out of memory normalizing numeric labels");goto bad;}
  int quote=0,escape=0;size_t pos=0;
  while(isspace((unsigned char)src[pos]))pos++;
  int numeric_def=isdigit((unsigned char)src[pos])&&src[pos+1]==':';
  for(size_t j=0;src[j];){
   if(src[j]=='#'&&!quote){while(src[j])dst[used++]=src[j++];break;}
   if(src[j]=='\\'&&quote&&!escape){dst[used++]=src[j++];escape=1;continue;}
   if(!escape&&((!quote&&(src[j]=='"'||src[j]=='\''))||src[j]==quote))
    quote=quote?0:src[j];
   if(!quote&&!escape&&numeric_def&&j==pos){
    if(!append_numeric_name(&dst,&used,&cap,prefix,src[j]-'0',i,length-j-1)){err("out of memory normalizing numeric labels");free(dst);goto bad;}
    j++;continue;
   }
   if(!quote&&!escape&&isdigit((unsigned char)src[j])&&(src[j+1]=='f'||src[j+1]=='b')&&
      (j==0||!(isalnum((unsigned char)src[j-1])||src[j-1]=='_'||src[j-1]=='.'))&&
      !(isalnum((unsigned char)src[j+2])||src[j+2]=='_'||src[j+2]=='.')){
    int d=src[j]-'0',forward=src[j+1]=='f';size_t target=count;
    if(forward){for(size_t k=i+1;k<count;k++)if(defs[d][k]){target=k;break;}}
    else {target=count;for(size_t k=0;k<=i&&k<count;k++)if(defs[d][k])target=k;}
    if(target==count){err(forward?"unresolved forward numeric label":"unresolved backward numeric label");free(dst);goto bad;}
    if(!append_numeric_name(&dst,&used,&cap,prefix,d,target,length-j-2)){err("out of memory normalizing numeric labels");free(dst);goto bad;}
    j+=2;continue;
   }
   dst[used++]=src[j++];if(escape)escape=0;
  }
  dst[used]=0;free(lines[i].text);lines[i].text=dst;
 }
 for(int d=0;d<10;d++)free(defs[d]);
 return 1;
 bad:
 for(int d=0;d<10;d++)free(defs[d]);
 return 0;
}

static void assemble(char *line){if(!lock_prefix_active)instruction_start=section_offset();segment_prefix_emitted=0;line=trim(line);if(!*line)return;strip_comment(line);line=trim(line);if(!*line)return;
 /* Instruction prefixes are parsed recursively so they precede REX/operand-size bytes. */
 char *first=line;while(*first&&!isspace((unsigned char)*first))first++;char savep=*first;*first=0;
 if(!strcmp(line,"lock")||!strcmp(line,"rep")||!strcmp(line,"repe")||!strcmp(line,"repz")||!strcmp(line,"repne")||!strcmp(line,"repnz")){
   int islock=!strcmp(line,"lock"), isrepne=!strcmp(line,"repne")||!strcmp(line,"repnz");
   *first=savep;char *rest=trim(first);if(!*rest){err("instruction prefix requires an instruction");return;}
   char *mend=rest;while(*mend&&!isspace((unsigned char)*mend))mend++;char save=*mend;*mend=0;
   int valid=0;
   if(islock)valid=!strcmp(rest,"xadd")||!strcmp(rest,"xaddb")||!strcmp(rest,"xaddw")||!strcmp(rest,"xaddl")||!strcmp(rest,"xaddq")||!strcmp(rest,"cmpxchg")||!strcmp(rest,"cmpxchgb")||!strcmp(rest,"cmpxchgw")||!strcmp(rest,"cmpxchgl")||!strcmp(rest,"cmpxchgq")||!strcmp(rest,"cmpxchg8b")||!strcmp(rest,"cmpxchg16b");
   else valid=(!strncmp(rest,"movs",4)||!strncmp(rest,"cmps",4)||!strncmp(rest,"stos",4)||!strncmp(rest,"lods",4)||!strncmp(rest,"scas",4));
   *mend=save;if(!valid){err(islock?"lock currently supports xadd/cmpxchg forms":"rep prefixes require a supported string instruction");return;}
   if(islock){emit(0xf0,1);lock_prefix_active=1;}else{rep_prefix_active=1;repne_prefix_active=isrepne;}
   assemble(rest);
   lock_prefix_active=rep_prefix_active=repne_prefix_active=0;return;
 }
 *first=savep;
 char *colon=strchr(line,':');if(colon&&line[0]!='%'&&(!strchr(line,' ')||colon<strchr(line,' '))&&(!strchr(line,'\t')||colon<strchr(line,'\t'))){*colon=0;char *name=trim(line);if(!valid_symbol_name(name)){err("invalid label name");return;}Sym *s=symget(name);if(s){if(s->defined)err("duplicate label");s->defined=1;s->value=section_offset();s->section=current_section;}line=trim(colon+1);if(!*line)return;}
 if(*line=='.'){directive(line);return;}
 char *sp=line;while(*sp&&!isspace((unsigned char)*sp))sp++;char save=*sp;*sp=0;char mn[32];snprintf(mn,sizeof mn,"%s",line);*sp=save;char *args=trim(sp);int w=width_suffix(mn);size_t ml=strlen(mn);if(w)mn[ml-1]=0;
 /* String instructions use implicit RSI/RDI/RCX operands. */
 if((strncmp(mn,"movs",4)||strlen(mn)<=5) &&
    (!strncmp(mn,"movs",4)||!strncmp(mn,"cmps",4)||!strncmp(mn,"stos",4)||!strncmp(mn,"lods",4)||!strncmp(mn,"scas",4))){
   size_t z=strlen(mn);int sw=0;if(z==5){char c=mn[4];sw=c=='b'?8:c=='w'?16:c=='l'?32:c=='q'?64:0;}
   if(!sw||*args){err("string instruction requires b/w/l/q suffix and no explicit operands");return;}
   emit_string(!strncmp(mn,"movs",4)?"movs":!strncmp(mn,"cmps",4)?"cmps":!strncmp(mn,"stos",4)?"stos":!strncmp(mn,"lods",4)?"lods":"scas",sw);return;
 }
 if(!strcmp(mn,"stmxcsr")||!strcmp(mn,"ldmxcsr")){
   Op a;if(!parseop(args,&a)||a.kind!=3){err("MXCSR instruction requires a memory operand");return;}
   rex(0,0,a.index,a.rip?-1:a.base,0);emit(0x0f,1);emit(0xae,1);
   modrm(!strcmp(mn,"ldmxcsr")?2:3,&a);return;
 }
 if(!strcmp(mn,"ucomisd")||!strcmp(mn,"mulsd")||!strcmp(mn,"addsd")||!strcmp(mn,"subsd")||!strcmp(mn,"divsd")||!strcmp(mn,"pxor")||
    !strcmp(mn,"ucomiss")||!strcmp(mn,"mulss")||!strcmp(mn,"addss")||!strcmp(mn,"subss")||!strcmp(mn,"divss")||!strcmp(mn,"cvtss2sd")||!strcmp(mn,"cvtsd2ss")||
    !strcmp(mn,"cvttsd2si")||!strcmp(mn,"cvttsd2sil")||!strcmp(mn,"cvttsd2siq")||
    !strcmp(mn,"cvtsi2sd")||!strcmp(mn,"cvtsi2sdl")||!strcmp(mn,"cvtsi2sdq")||
    !strcmp(mn,"cvtsi2ss")||!strcmp(mn,"cvtsi2ssl")||!strcmp(mn,"cvtsi2ssq")){
   char *v[2];int n=split_operands(args,v,2);Op a,b;
   if(n!=2||!parseop(v[0],&a)||!parseop(v[1],&b)){err("invalid SSE operands");return;}
   if(!strncmp(mn,"cvttsd2si",9)){
     int width=mn[9]=='q'?64:mn[9]=='l'?32:b.width;
     emit_cvttsd2si(a,b,width);
   }else if(!strncmp(mn,"cvtsi2sd",8)||!strncmp(mn,"cvtsi2ss",8)){
     int width=mn[8]=='q'?64:mn[8]=='l'?32:a.width;
     emit_cvtsi2sd(a,b,width,mn[7]=='s');
   }else emit_sse_binary(mn,a,b);
   return;
 }
 if(emit_x87(mn,args))return;
 if(!strcmp(mn,"mov") && emit_special_mov(args))return;
 if(!strcmp(mn,"cmpxchg8b")||!strcmp(mn,"cmpxchg16b")){Op d;if(!parseop(args,&d)){err("cmpxchg8b/16b requires a memory operand");return;}emit_cmpxchg_wide(d,!strcmp(mn,"cmpxchg16b"));return;}
 if(!strcmp(mn,"xadd")||!strcmp(mn,"cmpxchg")){char *v[2];int n=split_operands(args,v,2);Op a,b;if(n!=2||!parseop(v[0],&a)||!parseop(v[1],&b)){err("xadd/cmpxchg require source,destination");return;}w=op_width(a,b,w);emit_atomic(mn,a,b,w);return;}

 /* Two-suffix AT&T move-extension mnemonics: movzbl, movzwq, movsbq, movslq. */
 if(!strncmp(mn,"movz",4)||!strncmp(mn,"movs",4)){
   int sw=0,dw=0;size_t z=strlen(mn);
   if(!strcmp(mn,"movsxd")){sw=32;dw=64;}
   else if(z==6){char a=mn[4],b=mn[5];sw=a=='b'?8:a=='w'?16:a=='l'?32:0;dw=b=='w'?16:b=='l'?32:b=='q'?64:0;}
   if(!sw||!dw){err("invalid movzx/movsx mnemonic suffix");return;}
   char *v[2];int n=split_operands(args,v,2);Op a,b;
   if(n!=2||!parseop(v[0],&a)||!parseop(v[1],&b)){err("invalid movzx/movsx operands");return;}
   emit_mov_extend(mn,a,b,sw,dw);return;
 }
 int cc;
 if(parse_cc_mnemonic(mn,"set",&cc)){Op d;if(!parseop(args,&d)){err("invalid setcc destination");return;}emit_setcc(cc,d);return;}
 if(!strncmp(mn,"cmov",4)){
   size_t z=strlen(mn);if(z<=4){err("cmovcc requires a condition");return;}
   cc=condition_code(mn+4);
   if(cc<0&&z>5){
    char suffix=mn[z-1];w=suffix=='w'?16:suffix=='l'?32:suffix=='q'?64:0;
    if(w){char cond[16];size_t cn=z-5;if(cn>=sizeof cond){err("invalid cmovcc condition");return;}
     memcpy(cond,mn+4,cn);cond[cn]=0;cc=condition_code(cond);}
   }
   if(cc<0){err("unknown cmovcc condition");return;}
   char *v[2];int n=split_operands(args,v,2);Op a,b;
   if(n!=2||!parseop(v[0],&a)||!parseop(v[1],&b)){err("invalid cmovcc operands");return;}
   if(!w)w=op_width(a,b,w);
   emit_cmovcc(cc,a,b,w);return;
 }
 if(!strcmp(mn,"bswap")){Op a;if(!parseop(args,&a)){err("invalid bswap operand");return;}w=op_width(a,a,w);emit_bswap(a,w);return;}
 if(!strcmp(mn,"lar")||!strcmp(mn,"lsl")){
   char *v[2];int n=split_operands(args,v,2);Op a,b;
   if(n!=2||!parseop(v[0],&a)||!parseop(v[1],&b)){err("lar/lsl require source,destination");return;}
   w=w?w:(b.width?b.width:32);emit_lar_lsl(mn,a,b,w);return;
 }
 if(!strcmp(mn,"verr")||!strcmp(mn,"verw")){Op a;if(!parseop(args,&a)){err("invalid verr/verw operand");return;}emit_verr_verw(mn,a);return;}
 if(!strcmp(mn,"lzcnt")||!strcmp(mn,"tzcnt")||!strcmp(mn,"popcnt")){
   char *v[2];int n=split_operands(args,v,2);Op a,b;
   if(n!=2||!parseop(v[0],&a)||!parseop(v[1],&b)){err("lzcnt/tzcnt/popcnt require source,destination");return;}
   w=op_width(b,b,w);emit_bitcount(mn,a,b,w);return;
 }
 if(!strcmp(mn,"bt")||!strcmp(mn,"bts")||!strcmp(mn,"btr")||!strcmp(mn,"btc")){
   char *v[2];int n=split_operands(args,v,2);Op a,b;
   if(n!=2||!parseop(v[0],&a)||!parseop(v[1],&b)){err("invalid bit operation operands");return;}
   w=op_width(b,b,w);emit_bitop(mn,a,b,w);return;
 }
 if(!strcmp(mn,"bsf")||!strcmp(mn,"bsr")){
   char *v[2];int n=split_operands(args,v,2);Op a,b;
   if(n!=2||!parseop(v[0],&a)||!parseop(v[1],&b)){err("invalid bit scan operands");return;}
   w=op_width(b,b,w);emit_scan(mn,a,b,w);return;
 }

 if(!strcmp(mn,"inc")||!strcmp(mn,"dec")||!strcmp(mn,"neg")||!strcmp(mn,"not")){
   Op a;if(!parseop(args,&a)){err("invalid unary operand");return;}w=op_width(a,a,w);emit_unary(mn,a,w);return;
 }
 if(!strcmp(mn,"rol")||!strcmp(mn,"ror")||!strcmp(mn,"rcl")||!strcmp(mn,"rcr")||!strcmp(mn,"shl")||!strcmp(mn,"sal")||!strcmp(mn,"shr")||!strcmp(mn,"sar")){
   char *v[2];int n=split_operands(args,v,2);
   Op count={.kind=1,.disp=1},dst;
   if(n==1){if(!parseop(v[0],&dst)){err("invalid shift operand");return;}}
   else if(n==2){if(!parseop(v[0],&count)||!parseop(v[1],&dst)){err("invalid shift operand");return;}}
   else {err("shift requires destination or count,destination");return;}
   w=op_width(dst,dst,w);emit_shift(mn,count,dst,w);return;
 }
 if(!strcmp(mn,"mul")||!strcmp(mn,"imul")||!strcmp(mn,"div")||!strcmp(mn,"idiv")){
   char *v[3];int n=split_operands(args,v,3);if(n<1){err("invalid multiply/divide operands");return;}
   Op a,b,c;if(!parseop(v[0],&a)){err("invalid multiply/divide operand");return;}
   if(n==1){w=op_width(a,a,w);emit_muldiv(mn,a,w);return;}
   if(strcmp(mn,"imul")){err("mul/div/idiv accept one operand");return;}
   if(n==2){if(!parseop(v[1],&b)){err("invalid imul destination");return;}w=op_width(b,b,w);if(a.kind==1)emit_imul3(a,b,b,w);else emit_imul2(a,b,w);return;}
   if(n==3){if(!parseop(v[1],&b)||!parseop(v[2],&c)){err("invalid imul operands");return;}w=op_width(c,c,w);emit_imul3(a,b,c,w);return;}
   err("imul accepts one, two, or three operands");return;
 }
 if(!strcmp(mn,"push")||!strcmp(mn,"pop")){Op a;if(!parseop(args,&a)){err("invalid push/pop operand");return;}if(!w)w=a.width?a.width:64;emit_pushpop(mn,a,w);return;}
 if(!strcmp(mn,"enter")){char *v[2];int n=split_operands(args,v,2);Op a,b;if(n!=2||!parseop(v[0],&a)||!parseop(v[1],&b)||a.kind!=1||b.kind!=1||a.symbol||b.symbol||a.disp<0||a.disp>65535||b.disp<0||b.disp>255){err("enter expects $allocation,$nesting immediates");return;}emit(0xc8,1);emit((uint16_t)a.disp,2);emit((uint8_t)b.disp,1);return;}
 if(!strcmp(mn,"leave")){if(*args)err("leave takes no operands");else emit(0xc9,1);return;}
 if(!strcmp(mn,"ret")){
   int rw=w?w:64;
   if(rw==32){err("retl is not valid in 64-bit mode");return;}
   if(!*args){if(rw==16)emit(0x66,1);emit(0xc3,1);return;}
   Op a;if(!parseop(args,&a)||a.kind!=1||a.symbol||a.disp<0||a.disp>65535){err("ret expects an optional unsigned 16-bit immediate");return;}
   if(rw==16){emit(0x66,1);}
   emit(0xc2,1);emit((uint16_t)a.disp,2);return;
 }
 if(!strcmp(mn,"rdrand")||!strcmp(mn,"rdseed")){Op a;if(!parseop(args,&a)){err("invalid rdrand/rdseed operand");return;}w=w?w:(a.width?a.width:32);emit_random(mn,a,w);return;}
 if(!strcmp(mn,"rdmsr")||!strcmp(mn,"wrmsr")){if(*args)err("rdmsr/wrmsr take no operands");else {emit(0x0f,1);emit(!strcmp(mn,"rdmsr")?0x32:0x30,1);}return;}
 if(!strcmp(mn,"lfence")||!strcmp(mn,"mfence")||!strcmp(mn,"sfence")){if(*args){err("fence instruction takes no operands");return;}emit(0x0f,1);emit(0xae,1);emit(!strcmp(mn,"lfence")?0xe8:!strcmp(mn,"mfence")?0xf0:0xf8,1);return;}
 if(!strcmp(mn,"cqo")||!strcmp(mn,"cqto")||!strcmp(mn,"cdq")||!strcmp(mn,"cltd")||!strcmp(mn,"cwd")||!strcmp(mn,"cbw")||!strcmp(mn,"cwde")||!strcmp(mn,"cltq")){
   if(*args){err("conversion instruction takes no operands");return;}
   if(!strcmp(mn,"cqo")||!strcmp(mn,"cqto")||!strcmp(mn,"cltq"))emit(0x48,1);
   else if(!strcmp(mn,"cwd")||!strcmp(mn,"cbw"))emit(0x66,1);
   emit((!strcmp(mn,"cbw")||!strcmp(mn,"cwde")||!strcmp(mn,"cltq"))?0x98:0x99,1);return;
 }
 if(!strcmp(mn,"lahf")||!strcmp(mn,"sahf")||!strcmp(mn,"pushfq")||!strcmp(mn,"popfq")){if(*args){err("flag instruction takes no operands");return;}emit(!strcmp(mn,"lahf")?0x9f:!strcmp(mn,"sahf")?0x9e:!strcmp(mn,"pushfq")?0x9c:0x9d,1);return;}
 if(!strcmp(mn,"swapgs")){if(*args)err("swapgs takes no operands");else {emit(0x0f,1);emit(0x01,1);emit(0xf8,1);}return;}
 if(!strcmp(mn,"invlpg")){
   Op a;if(!parseop(args,&a)||a.kind!=3){err("invlpg requires one memory operand");return;}
   rex(0,7,a.index,a.rip?-1:a.base,0);emit(0x0f,1);emit(0x01,1);modrm(7,&a);return;
 }
 if(!strcmp(mn,"nop")){if(*args)err("nop takes no operands");else emit(0x90,1);return;}
 if(!strcmp(mn,"endbr64")){if(*args)err("endbr64 takes no operands");else {emit(0xf3,1);emit(0x0f,1);emit(0x1e,1);emit(0xfa,1);}return;}
 if(!strcmp(mn,"syscall")){if(*args)err("syscall takes no operands");else {emit(0x0f,1);emit(0x05,1);}return;}
 if(!strcmp(mn,"sysret")||!strcmp(mn,"sysretq")){if(*args)err("sysret takes no operands");else {emit(0x48,1);emit(0x0f,1);emit(0x07,1);}return;}
 if(!strcmp(mn,"iretq")){if(*args)err("iretq takes no operands");else {emit(0x48,1);emit(0xcf,1);}return;}
 if(!strcmp(mn,"cpuid")){if(*args)err("cpuid takes no operands");else {emit(0x0f,1);emit(0xa2,1);}return;}
 if(!strcmp(mn,"rdtsc")){if(*args)err("rdtsc takes no operands");else {emit(0x0f,1);emit(0x31,1);}return;}
 if(!strcmp(mn,"rdtscp")){if(*args)err("rdtscp takes no operands");else {emit(0x0f,1);emit(0x01,1);emit(0xf9,1);}return;}
 if(!strcmp(mn,"pause")){if(*args)err("pause takes no operands");else {emit(0xf3,1);emit(0x90,1);}return;}
 if(!strcmp(mn,"hlt")){if(*args)err("hlt takes no operands");else emit(0xf4,1);return;}
 if(!strcmp(mn,"ud2")){if(*args)err("ud2 takes no operands");else {emit(0x0f,1);emit(0x0b,1);}return;}
 if(!strcmp(mn,"int3")){if(*args)err("int3 takes no operands");else emit(0xcc,1);return;}
 if(!strcmp(mn,"int")){Op a;if(!parseop(args,&a)||a.kind!=1||a.symbol||a.disp<0||a.disp>255){err("int expects an unsigned 8-bit immediate");return;}emit(0xcd,1);emit((uint8_t)a.disp,1);return;}
 if(!strcmp(mn,"cld")||!strcmp(mn,"std")||!strcmp(mn,"cli")||!strcmp(mn,"sti")||!strcmp(mn,"clc")||!strcmp(mn,"stc")||!strcmp(mn,"cmc")){if(*args){err("flag instruction takes no operands");return;}emit(!strcmp(mn,"cld")?0xfc:!strcmp(mn,"std")?0xfd:!strcmp(mn,"cli")?0xfa:!strcmp(mn,"sti")?0xfb:!strcmp(mn,"clc")?0xf8:!strcmp(mn,"stc")?0xf9:0xf5,1);return;}
 if(!strcmp(mn,"call")||!strcmp(mn,"jmp")){
   char *target=trim(args);
   if(*target=='*'){
     Op ind;if(!parseop(target+1,&ind)||(ind.kind!=2&&ind.kind!=3)){err("indirect call/jmp requires register or memory operand");return;}
     if(ind.kind==2&&ind.width!=64){err("indirect call/jmp requires a 64-bit register");return;}
     if(ind.reloc_type==R_X86_64_TLSDESC_CALL && strcmp(mn,"call")){err("@TLSCALL is valid only on indirect call");return;}
     if(ind.reloc_type==R_X86_64_TLSDESC_CALL) relocation(ind.symbol,R_X86_64_TLSDESC_CALL,0);
     rex(0,(!strcmp(mn,"call")?2:4),ind.index,ind.kind==2?ind.reg:(ind.rip?-1:ind.base),0);
     emit(0xff,1);modrm(!strcmp(mn,"call")?2:4,&ind);return;
   }
   if(*target=='$'){err("immediate call/jmp is not supported; use a label or *register");return;}
   const char *sym=NULL;int64_t add=0;int ok=0;uint32_t branch_reloc=R_X86_64_PC32;number(target,&ok);
   int mr=split_relocation_modifier(target,&branch_reloc);if(mr<0)return;if(mr==0)branch_reloc=R_X86_64_PC32;else if(branch_reloc!=R_X86_64_PLT32){err("only @PLT is valid on direct call/jmp targets");return;}
   if(ok||!symbol_expr(target,&sym,&add)){err("invalid direct branch target");return;}
   size_t insn=*section_size();int isjmp=!strcmp(mn,"jmp");int use_short=isjmp&&current_line<nlines&&short_lines[current_line];
   if(use_short){emit(0xeb,1);size_t field=*section_size();emit(0,1);record_branch(BRANCH_JUMP,0,sym,add,1,insn,field,1,branch_reloc);}
   else {emit(isjmp?0xe9:0xe8,1);size_t field=*section_size();emit(0,4);record_branch(isjmp?BRANCH_JUMP:BRANCH_CALL,0,sym,add,0,insn,field,4,branch_reloc);}
   return;
 }
 if(!strcmp(mn,"loop")||!strcmp(mn,"loope")||!strcmp(mn,"loopz")||!strcmp(mn,"loopne")||!strcmp(mn,"loopnz")){
   const char *sym=NULL;int64_t add=0;int ok=0;(void)number(args,&ok);
   if(ok||!symbol_expr(trim(args),&sym,&add)){err("loop target must be a symbol expression");return;}
   if(add==INT64_MIN){err("loop relocation addend out of range");return;}
   uint8_t opcode=(!strcmp(mn,"loop")?0xe2:(!strcmp(mn,"loope")||!strcmp(mn,"loopz"))?0xe1:0xe0);
   size_t insn=*section_size();emit(opcode,1);size_t field=*section_size();emit(0,1);
   record_branch(BRANCH_LOOP,0,sym,add,1,insn,field,1,R_X86_64_PC8);return;
 }
 if(parse_cc_mnemonic(mn,"j",&cc)){
   const char *sym=NULL;int64_t add=0;int ok=0;(void)number(args,&ok);
   if(ok||!symbol_expr(trim(args),&sym,&add)){err("conditional branch target must be a symbol expression");return;}
   size_t insn=*section_size();int use_short=current_line<nlines&&short_lines[current_line];
   if(use_short){emit(0x70+cc,1);size_t field=*section_size();emit(0,1);record_branch(BRANCH_CONDITIONAL,cc,sym,add,1,insn,field,1,R_X86_64_PC32);}
   else {emit(0x0f,1);emit(0x80+cc,1);size_t field=*section_size();emit(0,4);record_branch(BRANCH_CONDITIONAL,cc,sym,add,0,insn,field,4,R_X86_64_PC32);}
   return;
 }
 char *comma=NULL;int depth=0;for(char *q=args;*q;q++){if(*q=='(')depth++;else if(*q==')')depth--;else if(*q==','&&depth==0){comma=q;break;}}if(!comma){err("expected two operands");return;}*comma=0;Op a,b;if(!parseop(args,&a)||!parseop(comma+1,&b)){err("invalid operand");return;}
 if(!strcmp(mn,"movups")){
  if(b.kind==4&&(a.kind==3||a.kind==4)){
   rex(0,b.reg,a.index,a.kind==4?a.reg:(a.rip?-1:a.base),0);
   emit(0x0f,1);emit(0x10,1);modrm(b.reg,&a);return;
  }
  if(a.kind==4&&b.kind==3){
   rex(0,a.reg,b.index,b.rip?-1:b.base,0);
   emit(0x0f,1);emit(0x11,1);modrm(a.reg,&b);return;
  }
  err("movups requires XMM and XMM/memory operands");return;
 }
 if(!strcmp(mn,"lea")||!strcmp(mn,"test")||!strcmp(mn,"xchg")){emit_two(mn,a,b,w);return;}
 if(!strcmp(mn,"mov")||!strcmp(mn,"movabs")){if(a.kind==4||b.kind==4){if(strcmp(mn,"mov"))err("movabs does not support XMM operands");else emit_xmm_mov(a,b,w);}else movlike(mn,a,b,w);return;}
 struct {const char*n;uint8_t op8,op,group;} tab[]={{"add",0x00,0x01,0},{"or",0x08,0x09,1},{"adc",0x10,0x11,2},{"sbb",0x18,0x19,3},{"and",0x20,0x21,4},{"sub",0x28,0x29,5},{"xor",0x30,0x31,6},{"cmp",0x38,0x39,7}};
 for(size_t i=0;i<sizeof tab/sizeof tab[0];i++)if(!strcmp(mn,tab[i].n)){if(!w)w=b.width?b.width:a.width;if(!w)w=32;if(a.kind==1){
     if(b.kind!=2&&b.kind!=3){err("immediate arithmetic destination must be register or memory");return;}
     if(b.kind==2&&b.width!=w){err("register width does not match instruction width");return;}
     int ok=1; int64_t imm=a.disp;
     if(a.symbol){err("symbolic arithmetic immediates are not supported");return;}
     if(w==8){if(imm < -128 || imm > 255)ok=0;}
     else if(w==16){if(imm < -32768 || imm > 65535)ok=0;}
     else if(w==32){if(imm < INT32_MIN || imm > UINT32_MAX)ok=0;}
     else if(w==64){if(imm < INT32_MIN || imm > INT32_MAX)ok=0;}
     if(!ok){err("arithmetic immediate out of range");return;}
     if(w==16)emit(0x66,1);
     /* Accumulator-special immediate encodings (AL/AX/EAX/RAX). */
     if(b.kind==2 && b.reg==0){
       rex(w==64,0,0,0,0);
       emit((w==8?tab[i].op8:tab[i].op)+4,1);
       emit((uint64_t)imm,w==8?1:(w==64?4:w/8));
       return;
     }
     rex(w==64,0,b.index<0?0:b.index,b.kind==2?b.reg:(b.rip?-1:b.base),w==8&&b.kind==2&&b.reg>=4);
     int use8=(w!=8 && imm>=-128 && imm<=127);
     int bytes=w==8?1:use8?1:(w==64?4:w/8);
     emit(w==8?0x80:use8?0x83:0x81,1);
     modrm_with_trailing(tab[i].group,&b,bytes);
     emit((uint64_t)imm,bytes);
     return;
   }
   if(a.kind==3&&b.kind==2){
     if(b.width!=w){err("register width does not match instruction width");return;}
     if(w==16)emit(0x66,1);
     rex(w==64,b.reg,a.index,a.rip?-1:a.base,w==8&&b.reg>=4);
     emit((w==8?tab[i].op8:tab[i].op)+2,1);modrm(b.reg,&a);return;
   }
   if(a.kind!=2){err("arithmetic source must be register or immediate");return;}
   if(b.kind!=2&&b.kind!=3){err("arithmetic destination must be register or memory");return;}
   if(!w)w=b.width?b.width:a.width;
   if(a.width&&a.width!=w){err("register width does not match instruction width");return;}
   if(b.width&&b.width!=w){err("register width does not match instruction width");return;}
   if(w==16)emit(0x66,1);
   rex(w==64,a.reg,b.index<0?0:b.index,b.kind==2?b.reg:(b.rip?-1:b.base),w==8&&(a.reg>=4||(b.kind==2&&b.reg>=4)));
   emit(w==8?tab[i].op8:tab[i].op,1);modrm(a.reg,&b);return;}
 err("unsupported instruction");
}
static unsigned char *section_data(int sec){ if(sec>=5&&sec<5+(int)ncustom_sections)return custom_sections[sec-5].data;return sec==1?text:sec==2?data:sec==4?rodata:NULL; }
static void finish_merge_sections(void){
 for(size_t i=0;i<ncustom_sections;i++){
  CustomSection *cs=&custom_sections[i];
  if(!(cs->flags&SHF_MERGE))continue;
  size_t align=cs->entsize&(~cs->entsize+1);
  size_t pad=(align-cs->size%align)%align;
  size_t cap=cs->type==SHT_NOBITS?NOBITS_CAP:SEC_CAP;
  if(cs->size>cap||pad>cap-cs->size){current_location=cs->location;err("mergeable section too large");return;}
  if(cs->type!=SHT_NOBITS)memset(cs->data+cs->size,(cs->flags&SHF_EXECINSTR)?0x90:0,pad);
  cs->size+=pad;
 }
}
static void reset_assembly_state(void){
 for(size_t i=0;i<ns;i++){free(syms[i]->name);free(syms[i]);}
 free(syms);free(symbol_buckets);syms=NULL;symbol_buckets=NULL;
 for(size_t i=0;i<nfile_symbols;i++)free(file_symbols[i]);
 free(file_symbols);file_symbols=NULL;nfile_symbols=file_symbol_capacity=0;
 symbol_capacity=symbol_bucket_count=0;
 for(size_t i=0;i<nsection_groups;i++)free(section_groups[i].signature);
 for(size_t i=0;i<nr;i++)free(rels[i].sym);
 free(rels);rels=NULL;rel_capacity=0;
 for(size_t i=0;i<nbranches;i++)free(branches[i].symbol);
 for(size_t i=0;i<ndiffs;i++){free(diffs[i].left);free(diffs[i].right);}
 for(size_t i=0;i<nsymvers;i++){free(symvers[i].source);free(symvers[i].alias);}
 nsymvers=0;ns=nr=nbranches=ndiffs=ncommon_allocations=0;nt=nd=nb=nro=0;for(size_t i=0;i<5;i++)base_align[i]=1;ncustom_sections=nsection_groups=0;section_stack_depth=0;current_section=1;memset(custom_sections,0,sizeof custom_sections);failed=0;
}
static void write_elf_symbol(Elf64_Sym *out,Sym *s,uint32_t index){
 s->elf_index=index;
 out->st_name=s->name_offset;
 out->st_info=ELF64_ST_INFO(s->bind,s->type);
 out->st_other=s->visibility;
 out->st_shndx=!s->defined?SHN_UNDEF:s->signature_group?(uint16_t)s->signature_group:s->section>=SHN_LORESERVE?(uint16_t)s->section:(uint16_t)(nsection_groups+s->section);
 out->st_value=s->value;out->st_size=s->size;
}
static void resolve_branches(int choose_short,int *changed,const SourceLine *lines){
 for(size_t i=0;i<nbranches;i++){
  Branch *b=&branches[i];Sym *sym=find_symbol(b->symbol);
  current_location=b->line>=0&&(size_t)b->line<nlines?lines[b->line].location:NULL;
  if(!sym||!sym->defined||sym->section!=b->section||sym->bind==STB_WEAK||
     (b->reloc_type==R_X86_64_PLT32&&sym->bind!=STB_LOCAL)||
     ((b->kind==BRANCH_CALL||b->kind==BRANCH_LOOP)&&sym->bind==STB_GLOBAL)){
   if(b->short_form&&b->kind!=BRANCH_LOOP){ if(choose_short&&b->line>=0&&(size_t)b->line<nlines&&short_lines[b->line]){short_lines[b->line]=0;*changed=1;} }
   if(!choose_short){
    if(b->addend<INT64_MIN+b->field_width){err("branch relocation addend out of range");continue;}
    uint32_t type=b->reloc_type;
    if(type==R_X86_64_PC32&&!b->addend&&(!sym||!sym->defined||sym->bind!=STB_LOCAL))type=R_X86_64_PLT32;
    relocation_at(b->symbol,type,b->addend-b->field_width,b->section,b->field_offset);
   }
   continue;
  }
  if(choose_short&&b->short_form&&b->kind!=BRANCH_LOOP){
   int64_t target,d;
   int64_t end=(int64_t)b->insn_offset+2;
   if((add_overflow64((int64_t)sym->value,b->addend,&target)||
       sub_overflow64(target,end,&d)||d< -128||d>127)&&
      b->line>=0&&(size_t)b->line<nlines&&short_lines[b->line]){
    short_lines[b->line]=0;*changed=1;
   }
  }
  if(!choose_short){
   int64_t target,d;
   if(add_overflow64((int64_t)sym->value,b->addend,&target)||
      sub_overflow64(target,(int64_t)b->field_offset+b->field_width,&d)){
    err("branch target out of range");continue;
   }
   if(b->field_width==1){if(d< -128||d>127){err(b->kind==BRANCH_LOOP?"loop target is out of range":"short branch is out of range");continue;}}
   else if(d<INT32_MIN||d>INT32_MAX){err("near branch is out of range");continue;}
   unsigned char *buf=section_data(b->section);if(!buf){err("branch in unsupported section");continue;}
   for(int k=0;k<b->field_width;k++)buf[b->field_offset+(size_t)k]=(unsigned char)((uint64_t)d>>(8*k));
  }
 }
}

static void resolve_differences(void){
 for(size_t i=0;i<ndiffs;i++){
  DiffFixup *f=&diffs[i];Sym *a=find_symbol(f->left),*b=find_symbol(f->right);
  current_location=f->location;
  if(!a||!b||!a->defined||!b->defined){err("unresolved symbol in section-relative expression");continue;}
  if(a->section!=b->section){err("symbol difference requires symbols in the same section");continue;}
  uint64_t magnitude=a->value>=b->value?a->value-b->value:b->value-a->value;
  if(magnitude>(uint64_t)INT64_MAX+(a->value<b->value)){err("symbol difference out of range");continue;}
  int64_t delta=a->value>=b->value?(int64_t)magnitude:(magnitude?-1-(int64_t)(magnitude-1):0),value;
  if(add_overflow64(delta,f->addend,&value)){err("symbol difference out of range");continue;}
  if(f->width==4&&(value<INT32_MIN||value>UINT32_MAX)){err("32-bit symbol difference out of range");continue;}
  unsigned char *buf=section_data(f->section);if(!buf){err("invalid section-relative expression section");continue;}
  for(int k=0;k<f->width;k++)buf[f->offset+(size_t)k]=(unsigned char)((uint64_t)value>>(8*k));
 }
}

static void resolve_symvers(void){
 for(size_t i=0;i<nsymvers;i++){
  current_location=symvers[i].location;
  Sym *src=find_symbol(symvers[i].source);if(!src||!src->defined){err(".symver source symbol is undefined");continue;}
  Sym *dst=symget(symvers[i].alias);if(!dst)continue;
  if(dst->defined){err(".symver alias is already defined");continue;}
  dst->value=src->value;dst->size=src->size;dst->bind=src->bind;dst->type=src->type;dst->visibility=src->visibility;dst->defined=1;dst->section=src->section;
 }
}

/* A deliberately bounded GNU-style macro expander. It runs once before
 * numeric-label normalization and branch relaxation, so expanded source is
 * identical in every assembly pass. */
typedef struct { char *name; char *params[32]; char *defaults[32]; unsigned char required[32]; size_t np; SourceLine *body; size_t nb; } Macro;
static Macro macros[256]; static size_t nmacros; static unsigned long macro_unique;
static int append_line(SourceLine **out,size_t *n,size_t *cap,const char *line,const SourceLocationNode *location){
 if(*n==*cap){size_t nc=*cap?*cap*2:256;SourceLine *q=realloc(*out,nc*sizeof *q);if(!q)return 0;*out=q;*cap=nc;}
 char *copy=strdup(line);if(!copy)return 0;
 (*out)[(*n)++]=(SourceLine){copy,location};return 1;
}
static Macro *macro_find(const char *name){for(size_t i=0;i<nmacros;i++)if(!strcmp(macros[i].name,name))return &macros[i];return NULL;}
static char *macro_argument(char *text){
 char *value=trim(text);
 if(*value=='"'){
  char *end=value+1;
  while(*end&&*end!='"'){if(*end=='\\'&&end[1])end++;end++;}
  if(*end!='"'||*trim(end+1)){err("invalid quoted macro argument");return NULL;}
  *end=0;return value+1;
 }
 for(char *p=value;*p;p++)if(isspace((unsigned char)*p)||*p=='"'||*p=='\''){
  err("unsupported macro argument syntax");return NULL;
 }
 return value;
}
static char *macro_argument_equals(char *text){
 int quote=0,escape=0;
 for(char *p=text;*p;p++){
  if(escape){escape=0;continue;}
  if(quote&&*p=='\\'){escape=1;continue;}
  if(*p=='"'||*p=='\''){if(!quote)quote=*p;else if(quote==*p)quote=0;continue;}
  if(!quote&&*p=='=')return p;
 }
 return NULL;
}
static char *macro_substitute(const char *src,Macro *m,char **args,size_t na,unsigned long uid){
 size_t cap=strlen(src)+128,used=0;char *out=malloc(cap);if(!out)return NULL;int quote=0,escaped=0;
 for(size_t i=0;src[i];){const char *rep=NULL;char num[40];size_t consumed=0;
  if(quote&&src[i]=='\\')escaped=!escaped;
  else {
   if(!escaped&&((!quote&&(src[i]=='"'||src[i]=='\''))||src[i]==quote))quote=quote?0:src[i];
   escaped=0;
  }
  if(src[i]=='\\'&&src[i+1]){
   if(src[i+1]=='@'){snprintf(num,sizeof num,"%lu",uid);rep=num;consumed=2;}
   else if(src[i+1]=='('&&src[i+2]==')'){consumed=3;rep="";}
   else if(src[i+1]=='{'){size_t j=i+2;while(src[j]&&src[j]!='}')j++;if(src[j]=='}'){char key[128];size_t z=j-(i+2);if(z<sizeof key){memcpy(key,src+i+2,z);key[z]=0;for(size_t k=0;k<m->np;k++)if(!strcmp(key,m->params[k])){rep=k<na?args[k]:m->defaults[k];break;}}consumed=j-i+1;}}
   else {size_t j=i+1;while(isalnum((unsigned char)src[j])||src[j]=='_')j++;if(j>i+1){char key[128];size_t z=j-i-1;if(z<sizeof key){memcpy(key,src+i+1,z);key[z]=0;for(size_t k=0;k<m->np;k++)if(!strcmp(key,m->params[k])){rep=k<na?args[k]:m->defaults[k];break;}}consumed=j-i;}}
   if(!rep)consumed=0;
  }
  if(!consumed){if(used+2>cap){cap*=2;char*q=realloc(out,cap);if(!q){free(out);return NULL;}out=q;}out[used++]=src[i++];continue;}
  if(!rep)rep="";
  if(!quote&&strchr(rep,'#')){err("unquoted macro substitution containing # is unsupported");free(out);return NULL;}
  size_t z=strlen(rep);while(used+z+1>cap){cap*=2;char*q=realloc(out,cap);if(!q){free(out);return NULL;}out=q;}memcpy(out+used,rep,z);used+=z;i+=consumed;escaped=0;
 }
 out[used]=0;return out;
}
static char *replace_macro_local(const char *src,char **names,size_t nn,unsigned long uid){
 size_t cap=strlen(src)+128,used=0;char *out=malloc(cap);if(!out)return NULL;
 for(size_t i=0;src[i];){
  if(isalpha((unsigned char)src[i])||src[i]=='_'||src[i]=='.'){
   size_t j=i+1;while(isalnum((unsigned char)src[j])||src[j]=='_'||src[j]=='.')j++;
   char tok[256];size_t z=j-i;if(z<sizeof tok){memcpy(tok,src+i,z);tok[z]=0;const char *rep=NULL;char generated[320];
    for(size_t k=0;k<nn;k++)if(!strcmp(tok,names[k])){snprintf(generated,sizeof generated,".Lcrunch-as_%lu_%s",uid,tok);rep=generated;break;}
    if(rep){z=strlen(rep);while(used+z+1>cap){cap*=2;char*q=realloc(out,cap);if(!q){free(out);return NULL;}out=q;}memcpy(out+used,rep,z);used+=z;i=j;continue;}
   }
   while(used+(j-i)+1>cap){cap*=2;char*q=realloc(out,cap);if(!q){free(out);return NULL;}out=q;}memcpy(out+used,src+i,j-i);used+=j-i;i=j;continue;
  }
  if(used+2>cap){cap*=2;char*q=realloc(out,cap);if(!q){free(out);return NULL;}out=q;}out[used++]=src[i++];
 }
 out[used]=0;return out;
}
static int process_macro_range(SourceLine **srcp,size_t *count,SourceLine **out,size_t *nout,size_t *cap,unsigned depth,int can_exit);
static int expand_macro_call(Macro *m,const char *call,SourceLine **out,size_t *nout,size_t *cap,unsigned depth){
 if(depth>32){err("macro expansion recursion limit exceeded");return 0;}
 const SourceLocationNode *call_location=current_location;
 char *copy=strdup(call);if(!copy)return 0;char *p=copy;while(*p&&!isspace((unsigned char)*p))p++;char *argtext=trim(p);char *av[32];int ac=*argtext?split_operands(argtext,av,32):0;
 if(ac<0){err("too many macro arguments");free(copy);return 0;}
 char *args[32]={0};char *locals[64]={0};size_t nl=0;for(size_t i=0;i<m->np;i++){args[i]=strdup(m->defaults[i]?m->defaults[i]:"");if(!args[i]){for(size_t j=0;j<i;j++)free(args[j]);free(copy);return 0;}}
 size_t positional=0;unsigned char assigned[32]={0};
 for(int ai=0;ai<ac;ai++){
  char *eq=macro_argument_equals(av[ai]);size_t slot=(size_t)-1;
  if(eq){*eq++=0;char *key=trim(av[ai]);for(size_t k=0;k<m->np;k++)if(!strcmp(key,m->params[k])){slot=k;break;}if(slot==(size_t)-1){err("unknown named macro argument");goto bad_args;}}
  else {while(positional<m->np&&assigned[positional])positional++;slot=positional++;if(slot>=m->np){err("too many macro arguments");goto bad_args;}}
  if(assigned[slot]){err("macro argument supplied more than once");goto bad_args;}
  char *value=macro_argument(eq?eq:av[ai]);if(!value)goto bad_args;
  if(m->required[slot]&&!*value){err("missing required macro argument");goto bad_args;}
  if(*value){char *v=strdup(value);if(!v)goto bad_args;free(args[slot]);args[slot]=v;}
  assigned[slot]=1;
 }
 for(size_t i=0;i<m->np;i++)if(m->required[i]&&!assigned[i]){err("missing required macro argument");goto bad_args;}
 unsigned long uid=macro_unique++;SourceLine *body=NULL;size_t nb=0,bc=0;
 for(size_t i=0;i<m->nb;i++){
  const SourceLocationNode *origin=m->body[i].location;
  unsigned include_depth=origin->include_depth>call_location->include_depth?
                         origin->include_depth:call_location->include_depth;
  const SourceLocationNode *expanded_location=source_location(origin->filename,origin->line,call_location,include_depth);
  if(!expanded_location)goto bad_body;
  current_location=expanded_location;
  char *lc=strdup(m->body[i].text);if(!lc)goto bad_body;char *lt=trim(lc);
  if(directive_is(lt,"LOCAL")){
   char *parts[64];int n=split_operands(trim(lt+5),parts,64);
   if(n<1||nl+(size_t)n>64){free(lc);err("invalid or excessive LOCAL symbols in macro");goto bad_body;}
   for(int k=0;k<n;k++){locals[nl]=strdup(trim(parts[k]));if(!locals[nl++]){free(lc);goto bad_body;}}
   free(lc);continue;
  }
  free(lc);
  char *expanded=macro_substitute(m->body[i].text,m,args,m->np,uid);
  char *localized=expanded?replace_macro_local(expanded,locals,nl,uid):NULL;free(expanded);
  if(!localized||!append_line(&body,&nb,&bc,localized,expanded_location)){free(localized);goto bad_body;}
  free(localized);
 }
 /* Process conditionals and nested macro calls after parameter substitution,
  * so .ifc/.ifnc can compare actual invocation arguments. .exitm is consumed
  * by this range and therefore exits only this invocation. */
 if(!process_macro_range(&body,&nb,out,nout,cap,depth+1,1))goto bad_body;
 for(size_t i=0;i<nb;i++){free(body[i].text);}
 free(body);
 for(size_t i=0;i<m->np;i++){free(args[i]);}
 for(size_t i=0;i<nl;i++)free(locals[i]);
 free(copy);return 1;
bad_body:
 for(size_t i=0;i<nb;i++){free(body[i].text);}
 free(body);
bad_args:
 for(size_t i=0;i<nl;i++)free(locals[i]);
 for(size_t i=0;i<m->np;i++){free(args[i]);}
 free(copy);return 0;
}

static int directive_is(const char *line,const char *d){
 size_t n=strlen(d);return !strncmp(line,d,n)&&(line[n]==0||isspace((unsigned char)line[n]));
}
static size_t preprocess_hash(const char *name){
 size_t hash=5381;
 for(;*name;name++)hash=hash*33+(unsigned char)*name;
 return hash;
}
static PreprocessConstant *preprocess_symbol(const char *name,int create){
 size_t bucket=preprocess_bucket_count?preprocess_hash(name)%preprocess_bucket_count:0;
 for(size_t i=preprocess_bucket_count?preprocess_buckets[bucket]:0;i;i=preprocess_constants[i-1].next)
  if(!strcmp(preprocess_constants[i-1].name,name))return &preprocess_constants[i-1];
 if(!create)return NULL;
 if(npreprocess_constants==preprocess_capacity){
  if(preprocess_capacity>SIZE_MAX/2/sizeof *preprocess_constants){err("too many preprocessing symbols");return NULL;}
  size_t capacity=preprocess_capacity?preprocess_capacity*2:64;
  PreprocessConstant *constants=realloc(preprocess_constants,capacity*sizeof *constants);
  if(!constants){err("out of memory recording preprocessing symbol");return NULL;}
  preprocess_constants=constants;preprocess_capacity=capacity;
 }
 if(npreprocess_constants>=preprocess_bucket_count){
  if(preprocess_bucket_count>SIZE_MAX/2/sizeof *preprocess_buckets){err("too many preprocessing symbols");return NULL;}
  size_t count=preprocess_bucket_count?preprocess_bucket_count*2:64;
  size_t *buckets=calloc(count,sizeof *buckets);
  if(!buckets){err("out of memory recording preprocessing symbol");return NULL;}
  for(size_t i=0;i<npreprocess_constants;i++){
   size_t slot=preprocess_hash(preprocess_constants[i].name)%count;
   preprocess_constants[i].next=buckets[slot];buckets[slot]=i+1;
  }
  free(preprocess_buckets);preprocess_buckets=buckets;preprocess_bucket_count=count;
  bucket=preprocess_hash(name)%count;
 }
 char *copy=strdup(name);if(!copy){err("out of memory recording preprocessing symbol");return NULL;}
 PreprocessConstant *symbol=&preprocess_constants[npreprocess_constants++];
 *symbol=(PreprocessConstant){.name=copy,.next=preprocess_buckets[bucket]};
 preprocess_buckets[bucket]=npreprocess_constants;return symbol;
}
static int preprocess_mark_defined(const char *name){
 PreprocessConstant *symbol=preprocess_symbol(name,1);
 if(!symbol)return 0;
 symbol->defined=1;return 1;
}
static int preprocess_is_defined(const char *name){
 if(!strcmp(name,".text")||!strcmp(name,".data")||!strcmp(name,".bss"))return 1;
 PreprocessConstant *symbol=preprocess_symbol(name,0);
 return symbol&&symbol->defined;
}
static int preprocess_definition(char *line,char **replacement){
 *replacement=NULL;char *label=NULL;
 char *colon=strchr(line,':'),*space=line;
 while(*space&&!isspace((unsigned char)*space))space++;
 if(colon&&colon<space){
  *colon=0;
  label=line;
  if(valid_symbol_name(line)&&!preprocess_mark_defined(line))return 0;
  line=trim(colon+1);
 }
 if(directive_is(line,".comm")||directive_is(line,".lcomm")){
  char *args=trim(line+(line[1]=='c'?5:6)),*comma=strchr(args,',');
  if(comma){*comma=0;args=trim(args);if(valid_symbol_name(args)&&!preprocess_mark_defined(args))return 0;}
  return 1;
 }
 if(directive_is(line,".section")||directive_is(line,".pushsection")){
  char *args=trim(line+(line[1]=='s'?8:12)),*comma=strchr(args,',');
  if(comma)*comma=0;
  args=trim(args);
  if(valid_symbol_name(args)&&!preprocess_mark_defined(args))return 0;
  return 1;
 }
 if(directive_is(line,".rodata")||directive_is(line,".tdata")||directive_is(line,".tbss")){
  char *end=line;while(*end&&!isspace((unsigned char)*end))end++;*end=0;
  return preprocess_mark_defined(line);
 }
 if(!directive_is(line,".equ")&&!directive_is(line,".set"))return 1;
 char *parts[2];int count=parse_csv(trim(line+4),parts,2);
 if(count!=2||!valid_symbol_name(parts[0])||!*parts[1])return 1;
 PreprocessConstant *symbol=preprocess_symbol(parts[0],0);
 int64_t value=0;int known=resolve_absolute_expr(parts[1],&value);
 if(!symbol)symbol=preprocess_symbol(parts[0],1);
 if(!symbol)return 0;
 symbol->defined=1;symbol->known=known;symbol->value=value;
 if(known){
  /* Freeze known values before later redefinitions can change the expression. */
  size_t n=strlen(parts[0])+(label?strlen(label):0)+64;
  *replacement=malloc(n);
  if(!*replacement){err("out of memory recording ordered definition");return 0;}
  snprintf(*replacement,n,"%s%s.set %s,%" PRId64,label?label:"",label?": ":"",parts[0],value);
 }
 return 1;
}
static int conditional_symbol(char *line,int *value){
 int inverse=directive_is(line,".ifndef");
 char *name=trim(line+(inverse?7:6));
 if(!valid_symbol_name(name)){err(".ifdef/.ifndef expects a single valid symbol");return 0;}
 *value=preprocess_is_defined(name);
 if(inverse)*value=!*value;
 return 1;
}
static int conditional_expression(char *expr,const char *directive,int *value){
 int64_t v=0;
 if(!resolve_absolute_expr(trim(expr),&v)){
  char message[96];snprintf(message,sizeof message,"%s requires an absolute expression",directive);
  err(message);return 0;
 }
 *value=v!=0;return 1;
}
static char *conditional_line(char *line,char **label){
 *label=NULL;
 char *colon=strchr(line,':'),*space=line;
 while(*space&&!isspace((unsigned char)*space))space++;
 if(!colon||colon>=space)return line;
 char *directive=trim(colon+1);
 if(!directive_is(directive,".if")&&!directive_is(directive,".ifc")&&
    !directive_is(directive,".ifnc")&&!directive_is(directive,".ifdef")&&
    !directive_is(directive,".ifndef")&&!directive_is(directive,".elseif")&&
    !directive_is(directive,".else")&&!directive_is(directive,".endif")&&
    !directive_is(directive,".include"))return line;
 *colon=0;
 if(!valid_symbol_name(line)&&!(isdigit((unsigned char)line[0])&&!line[1])){
  *colon=':';return line;
 }
 *label=line;return directive;
}
static int append_conditional_label(const char *label,const SourceLocationNode *location,
                                    SourceLine **out,size_t *nout,size_t *cap){
 if(valid_symbol_name(label)&&!preprocess_mark_defined(label))return 0;
 size_t n=strlen(label);char *text=malloc(n+2);
 if(!text){err("out of memory recording conditional label");return 0;}
 memcpy(text,label,n);text[n]=':';text[n+1]=0;
 int ok=append_line(out,nout,cap,text,location);
 free(text);return ok;
}
static int find_repetition_end(SourceLine *src,size_t from,size_t end,size_t *closepos){
 int depth=0;*closepos=(size_t)-1;
 for(size_t i=from;i<end;i++){
  char *c=strdup(src[i].text);if(!c){err("out of memory scanning repetition");return 0;}
  strip_comment(c);char *t=trim(c);
  if(directive_is(t,".rept")||directive_is(t,".irp")||directive_is(t,".irpc"))depth++;
  else if(directive_is(t,".endr")){if(depth==0){*closepos=i;free(c);return 1;}depth--;}
  free(c);
 }
 return 0;
}
static void free_lines(SourceLine *lines,size_t count);
static int parse_line_marker(const char *text,const char **filename,size_t *line_number);

static char *include_filename(char *operand){
 char *p=trim(operand);
 if(*p++!='"'){err(".include expects a quoted filename");return NULL;}
 char *name=malloc(strlen(p)+1);if(!name){err("out of memory parsing include filename");return NULL;}
 size_t n=0;
 while(*p&&*p!='"'){
  unsigned char c=(unsigned char)*p++;
  if(c=='\\'){
   if(!*p){free(name);err("unterminated include filename");return NULL;}
   c=(unsigned char)*p++;
   if(c=='x'||c=='X'){
    unsigned value=0;
    for(;;){
     unsigned char d=(unsigned char)*p;unsigned digit;
     if(d>='0'&&d<='9')digit=d-'0';
     else if(d>='a'&&d<='f')digit=d-'a'+10;
     else if(d>='A'&&d<='F')digit=d-'A'+10;
     else break;
     value=(value*16+digit)&255;p++;
    }
    c=(unsigned char)value;
   }else if(c>='0'&&c<='9'){
    unsigned value=c-'0';
    for(int i=1;i<3&&*p>='0'&&*p<='9';i++)value=value*8+(unsigned)(*p++-'0');
    c=(unsigned char)(value&255);
   }else if(c=='b')c='\b';else if(c=='f')c='\f';else if(c=='n')c='\n';
   else if(c=='r')c='\r';else if(c=='t')c='\t';else if(c=='v')c='\v';
  }
  if(!c){free(name);err("include filename contains a NUL byte");return NULL;}
  name[n++]=(char)c;
 }
 if(*p!='"'){free(name);err("unterminated include filename");return NULL;}
 if(*trim(p+1)){free(name);err("unexpected text after include filename");return NULL;}
 name[n]=0;return name;
}
static FILE *open_include(const char *name,char **resolved){
 *resolved=strdup(name);
 if(!*resolved){err("out of memory opening include");return NULL;}
 FILE *file=fopen(*resolved,"r");
 if(file||name[0]=='/')return file;
 int last_error=errno;
 for(size_t i=0;i<assembler_include_count;i++){
  size_t d=strlen(assembler_include_dirs[i]),n=strlen(name);
  if(d>SIZE_MAX-n-2){err("include path is too long");return NULL;}
  char *path=malloc(d+n+2);if(!path){err("out of memory opening include");return NULL;}
  memcpy(path,assembler_include_dirs[i],d);path[d]='/';memcpy(path+d+1,name,n+1);
  file=fopen(path,"r");
  if(file){free(*resolved);*resolved=path;return file;}
  if(errno!=ENOENT&&errno!=ENOTDIR)last_error=errno;
  free(path);
 }
 errno=last_error;return NULL;
}
static int insert_include(SourceLine **srcp,size_t *count,size_t index,char *operand){
 const SourceLocationNode *origin=(*srcp)[index].location;
 if(origin->include_depth>=64){err("assembler include nesting limit exceeded");return 0;}
 char *name=include_filename(operand);
 if(!name)return 0;
 char *path=NULL;FILE *file=open_include(name,&path);
 if(!file){
  if(!failed){
   char message[1024];snprintf(message,sizeof message,"cannot open include '%s': %s",name,strerror(errno));
   err(message);include_io_error=1;
  }
  free(name);free(path);return 0;
 }
 free(name);
 const char *filename=intern_filename(path);free(path);
 if(!filename){fclose(file);return 0;}
 SourceLine *included=NULL;size_t n=0,capacity=0,line_number=1,linecap=0;char *line=NULL;
 int ok=1;
 for(;;){
  errno=0;
  if(getline(&line,&linecap,file)<0)break;
  const SourceLocationNode *location=source_location(filename,line_number,origin->expanded_from,
                                                      origin->include_depth+1);
  if(!location||!append_line(&included,&n,&capacity,line,location)){
   if(!failed)err("out of memory reading include");
   ok=0;break;
  }
  current_location=location;
  int marker=parse_line_marker(line,&filename,&line_number);
  if(marker<0){ok=0;break;}
  if(!marker&&line_number<SIZE_MAX)line_number++;
 }
 free(line);
 if(ferror(file)||!feof(file)){
  char message[1024];snprintf(message,sizeof message,"cannot read include '%s': %s",filename,strerror(errno));
  current_location=origin;err(message);include_io_error=1;ok=0;
 }
 if(fclose(file)!=0){current_location=origin;err("cannot close include file");include_io_error=1;ok=0;}
 current_location=origin;
 if(!ok){free_lines(included,n);return 0;}
 if(n>SIZE_MAX-(*count-1)||(*count-1+n)>SIZE_MAX/sizeof(SourceLine)){
  free_lines(included,n);err("too many included assembly lines");return 0;
 }
 size_t total=*count-1+n;
 SourceLine *src=*srcp,*replacement=malloc((total?total:1)*sizeof *replacement);
 if(!replacement){free_lines(included,n);err("out of memory inserting include");return 0;}
 if(index)memcpy(replacement,src,index*sizeof *src);
 if(n)memcpy(replacement+index,included,n*sizeof *src);
 if(*count-index-1)memcpy(replacement+index+n,src+index+1,(*count-index-1)*sizeof *src);
 free(src[index].text);free(src);free(included);
 *srcp=replacement;*count=total;return 1;
}
static int process_macro_range(SourceLine **srcp,size_t *count,SourceLine **out,size_t *nout,size_t *cap,unsigned depth,int can_exit){
 if(depth>32){err("preprocessor nesting limit exceeded");return 0;}
 typedef struct { int parent,active,taken,seen_else;const SourceLocationNode *location; } Conditional;
 Conditional conditions[33];size_t nconditions=0;
 for(size_t i=0;i<*count;i++){
  SourceLine *src=*srcp;size_t end=*count;
  current_location=src[i].location;
  char *tmp=strdup(src[i].text);if(!tmp)return 0;strip_comment(tmp);char *t=trim(tmp);
  int active=!nconditions||conditions[nconditions-1].active;
  if(active){
   char *label=NULL,*conditional=conditional_line(t,&label);
   if(label){
    if(!append_conditional_label(label,src[i].location,out,nout,cap)){free(tmp);return 0;}
    t=conditional;
   }
  }
  if(directive_is(t,".if")||directive_is(t,".ifc")||directive_is(t,".ifnc")||
     directive_is(t,".ifdef")||directive_is(t,".ifndef")){
   const char *kind=directive_is(t,".if")?".if":directive_is(t,".ifc")?".ifc":
                    directive_is(t,".ifnc")?".ifnc":directive_is(t,".ifdef")?".ifdef":".ifndef";
   int yes=0;
   if(!strcmp(kind,".if")){if(active&&!conditional_expression(t+3,kind,&yes)){free(tmp);return 0;}}
   else if(!strcmp(kind,".ifdef")||!strcmp(kind,".ifndef")){
    if(!conditional_symbol(t,&yes)){free(tmp);return 0;}
   }
   else if(!strcmp(kind,".ifc")||!strcmp(kind,".ifnc")){
    char *a=trim(t+strlen(kind)),*comma=strchr(a,',');
    if(!comma){err(".ifc/.ifnc expects two strings");free(tmp);return 0;}
    *comma++=0;yes=!strcmp(trim(a),trim(comma));if(!strcmp(kind,".ifnc"))yes=!yes;
   }
   if(nconditions+depth>=32){err("preprocessor nesting limit exceeded");free(tmp);return 0;}
   conditions[nconditions++]=(Conditional){active,active&&yes,active&&yes,0,src[i].location};
   free(tmp);continue;
  }
  if(directive_is(t,".elseif")||directive_is(t,".else")||directive_is(t,".endif")){
   int is_elseif=directive_is(t,".elseif"),is_else=directive_is(t,".else");
   if(!nconditions){err("unexpected conditional/repetition terminator");free(tmp);return 0;}
   Conditional *condition=&conditions[nconditions-1];
   if(!is_elseif&&*trim(t+(is_else?5:6))){err("unexpected operands after conditional terminator");free(tmp);return 0;}
   if(!is_elseif&&!is_else){nconditions--;free(tmp);continue;}
   if(condition->seen_else){err(is_else?"duplicate .else":".elseif after .else");free(tmp);return 0;}
   if(is_else)condition->seen_else=1;
   int yes=1;
   if(is_elseif&&condition->parent&&!condition->taken&&
      !conditional_expression(t+7,".elseif",&yes)){free(tmp);return 0;}
   condition->active=condition->parent&&!condition->taken&&yes;
   if(condition->active)condition->taken=1;
   free(tmp);continue;
  }
  if(!active){free(tmp);continue;}
  if(directive_is(t,".include")){
   int ok=insert_include(srcp,count,i,trim(t+8));free(tmp);
   if(!ok)return 0;
   i--;continue;
  }
  if(directive_is(t,".exitm")){
   if(*trim(t+6)){err(".exitm does not accept operands");free(tmp);return 0;}
   if(!can_exit){err(".exitm outside a macro or repetition is unsupported");free(tmp);return 0;}
   free(tmp);return 2;
  }
  if(directive_is(t,".rept")||directive_is(t,".irp")||directive_is(t,".irpc")){
   int rept=directive_is(t,".rept"),irpc=directive_is(t,".irpc");size_t close;
   if(!find_repetition_end(src,i+1,end,&close)){if(!failed)err("unterminated repetition block");free(tmp);return 0;}
   char *bodyarg=trim(t+5);char *vals[256];char one[512];int nv=0;char *param=NULL;int64_t count=0;
   if(rept){if(!resolve_absolute_expr(bodyarg,&count)||count<0||count>100000){err("invalid .rept count");free(tmp);return 0;}}
   else {
    char *parts[256];int np=split_operands(bodyarg,parts,256);if(np<2){err(".irp/.irpc expects a parameter and values");free(tmp);return 0;}param=strdup(trim(parts[0]));
    if(!param){free(tmp);return 0;}
    if(irpc){
     const char *q=parts[1];
     if(np!=2||strlen(q)>256){err("unsupported or excessive .irpc character list");free(param);free(tmp);return 0;}
     for(const char *p=q;*p;p++)if(isspace((unsigned char)*p)||*p=='"'||*p=='\''||*p=='\\'){err("unsupported .irpc character list");free(param);free(tmp);return 0;}
     while(*q){one[nv*2]=*q++;one[nv*2+1]=0;vals[nv]=&one[nv*2];nv++;}
    }
    else for(int k=1;k<np;k++){
     char *value=macro_argument(parts[k]);
     if(!value){for(int j=0;j<nv;j++)free(vals[j]);free(param);free(tmp);return 0;}
     vals[nv]=strdup(value);if(!vals[nv]){for(int j=0;j<nv;j++)free(vals[j]);free(param);free(tmp);return 0;}nv++;
    }
   }
   const SourceLocationNode *repeat_location=current_location;
   free(tmp);
   Macro fake={0};if(param){fake.np=1;fake.params[0]=param;}
   int repetition_ok=1;unsigned long repeat_uid=macro_unique;
   for(int k=0;k<(rept?(int)count:nv);k++){
    SourceLine *expanded=NULL;size_t en=0,ec=0;
    for(size_t j=i+1;j<close;j++){
     char *line;
     const SourceLocationNode *origin=src[j].location;
     current_location=repeat_location;
     unsigned include_depth=origin->include_depth>repeat_location->include_depth?
                            origin->include_depth:repeat_location->include_depth;
     const SourceLocationNode *expanded_location=source_location(origin->filename,origin->line,repeat_location,include_depth);
     if(rept)line=strdup(src[j].text);else line=macro_substitute(src[j].text,&fake,&vals[k],1,repeat_uid);
     if(!expanded_location||!line||!append_line(&expanded,&en,&ec,line,expanded_location)){free(line);repetition_ok=0;break;}free(line);
    }
    int result=repetition_ok?process_macro_range(&expanded,&en,out,nout,cap,depth+1,1):0;
    if(!result)repetition_ok=0;
    for(size_t z=0;z<en;z++) free(expanded[z].text);
    free(expanded);
    if(!repetition_ok||result==2)break;
   }
   if(param) free(param);
   if(!irpc) for(int k=0;k<nv;k++) free(vals[k]);
   if(!repetition_ok)return 0;
   i=close;continue;
  }
  if(directive_is(t,".endr")){err("unexpected conditional/repetition terminator");free(tmp);return 0;}
  if(directive_is(t,".macro")){
   if(nmacros==256){err("too many macro definitions");free(tmp);return 0;}
   char *p=trim(t+6);char *e=p;while(*e&&!isspace((unsigned char)*e))e++;char save=*e;*e=0;
   if(macro_find(p)){err("macro already defined");free(tmp);return 0;}
   Macro *m=&macros[nmacros++];memset(m,0,sizeof *m);m->name=strdup(p);*e=save;
   if(!m->name){free(tmp);return 0;}
   char *pv=trim(e);char *parts[32];int np=*pv?split_operands(pv,parts,32):0;if(np<0){err("too many macro parameters");free(tmp);return 0;}
   for(int k=0;k<np;k++){
    char *eq=strchr(parts[k],'=');if(eq)*eq++=0;
    char *name=trim(parts[k]),*qualifier=strchr(name,':');
    if(qualifier){
     *qualifier++=0;qualifier=trim(qualifier);name=trim(name);
     if(strcmp(qualifier,"req")){err("unsupported macro parameter qualifier");free(tmp);return 0;}
     if(eq){err("default value for required macro parameter is unsupported");free(tmp);return 0;}
     m->required[m->np]=1;
    }
    if(!*name){err("macro parameter requires a name");free(tmp);return 0;}
    for(size_t j=0;j<m->np;j++)if(!strcmp(name,m->params[j])){err("duplicate macro parameter");free(tmp);return 0;}
    char *value=eq?macro_argument(eq):"";if(!value){free(tmp);return 0;}
    m->params[m->np]=strdup(name);m->defaults[m->np]=strdup(value);m->np++;
    if(!m->params[m->np-1]||!m->defaults[m->np-1]){free(tmp);return 0;}
   }
   size_t j=i+1;for(;j<end;j++){char *q=strdup(src[j].text);if(!q){free(tmp);return 0;}strip_comment(q);char *bt=trim(q);int done=!strcmp(bt,".endm");free(q);if(done)break;SourceLine *v=realloc(m->body,(m->nb+1)*sizeof *v);if(!v){free(tmp);return 0;}m->body=v;m->body[m->nb]=(SourceLine){strdup(src[j].text),src[j].location};if(!m->body[m->nb].text){free(tmp);return 0;}m->nb++;}
   if(j==end){err("unterminated .macro definition");free(tmp);return 0;}i=j;free(tmp);continue;
  }
  if(directive_is(t,".purgem")){Macro *m=macro_find(trim(t+7));if(m)m->name[0]=0;free(tmp);continue;}
  if(directive_is(t,".altmacro")){err(".altmacro is unsupported");free(tmp);return 0;}
  if(!strcmp(t,".noaltmacro")){free(tmp);continue;}
  char name[128];size_t z=0;while(t[z]&&!isspace((unsigned char)t[z])&&z<sizeof name-1)z++;memcpy(name,t,z);name[z]=0;Macro *m=macro_find(name);
  if(m){if(!expand_macro_call(m,t,out,nout,cap,depth)){free(tmp);return 0;}free(tmp);continue;}
  char *replacement=NULL;
  if(!preprocess_definition(t,&replacement)){free(tmp);return 0;}
  int appended=append_line(out,nout,cap,replacement?replacement:src[i].text,src[i].location);
  free(replacement);if(!appended){free(tmp);return 0;}free(tmp);
 }
 if(nconditions){current_location=conditions[nconditions-1].location;err("unterminated conditional assembly block");return 0;}
 return 1;
}
static int preprocess_macros(SourceLine **lines,size_t *count){
 SourceLine *src=*lines,*out=NULL;size_t nout=0,cap=0;
 evaluating_preprocess=1;int result=process_macro_range(&src,count,&out,&nout,&cap,0,0);
 evaluating_preprocess=0;
 for(size_t i=0;i<npreprocess_constants;i++)free(preprocess_constants[i].name);
 free(preprocess_constants);free(preprocess_buckets);
 preprocess_constants=NULL;preprocess_buckets=NULL;
 npreprocess_constants=preprocess_capacity=preprocess_bucket_count=0;
 if(!result){*lines=src;if(!failed)err("out of memory preprocessing assembly");for(size_t i=0;i<nout;i++)free(out[i].text);free(out);return 0;}
 for(size_t i=0;i<*count;i++) free(src[i].text);
 free(src); *lines=out; *count=nout; return 1;
}

static void free_lines(SourceLine *lines, size_t count){
 for(size_t i=0;i<count;i++)free(lines[i].text);
 free(lines);
}

/* Recognize the line markers emitted by the assembly preprocessor and GNU cpp. */
static int parse_line_marker(const char *text,const char **filename,size_t *line_number){
 const char *p=text;while(*p==' '||*p=='\t')p++;
 if(*p++!='#')return 0;
 while(*p==' '||*p=='\t')p++;
 if(!isdigit((unsigned char)*p))return 0;
 errno=0;char *end;unsigned long long number=strtoull(p,&end,10);
 if(errno==ERANGE||number>SIZE_MAX||(*end!=' '&&*end!='\t'))return 0;
 p=end;while(*p==' '||*p=='\t')p++;
 if(*p++!='"')return 0;
 char *name=malloc(strlen(p)+1);if(!name){err("out of memory parsing line marker");return -1;}
 size_t n=0;
 while(*p&&*p!='"'&&*p!='\n'){
  if(*p=='\\'&&(p[1]=='\\'||p[1]=='"'))p++;
  name[n++]=*p++;
 }
 if(*p!='"'){free(name);return 0;}
 name[n]=0;p++;
 while(*p==' '||*p=='\t')p++;
 while(isdigit((unsigned char)*p)){
  while(isdigit((unsigned char)*p))p++;
  if(*p&&*p!='\n'&&*p!='\r'&&*p!=' '&&*p!='\t'){free(name);return 0;}
  while(*p==' '||*p=='\t')p++;
 }
 if(*p&&*p!='\n'&&*p!='\r'){free(name);return 0;}
 const char *stored=intern_filename(name);free(name);if(!stored)return -1;
 *filename=stored;*line_number=(size_t)number;return 1;
}

static int assemble_files(const char *const *inputs, size_t ninputs, const char *output){
 report_warnings=0;
 SourceLine *lines=NULL;size_t linecap=0;char *line=NULL;size_t cap=0;ssize_t n;
 for(size_t fi=0;fi<ninputs;fi++){
   current_location=NULL;
   FILE *in=!strcmp(inputs[fi],"-")?stdin:fopen(inputs[fi],"r");if(!in){report_io_error(inputs[fi]);free(line);free_lines(lines,nlines);return 2;}
   const char *filename=intern_filename(!strcmp(inputs[fi],"-")?"<stdin>":inputs[fi]);
   size_t source_line=1;
   if(!filename){free(line);free_lines(lines,nlines);if(in!=stdin)fclose(in);return 1;}
   while((n=getline(&line,&cap,in))>=0){
     const SourceLocationNode *location=source_location(filename,source_line,NULL,0);
     if(!location||!append_line(&lines,&nlines,&linecap,line,location)){if(!failed)err("out of memory reading assembly");free(line);free_lines(lines,nlines);if(in!=stdin)fclose(in);return 1;}
     current_location=location;
     int marker=parse_line_marker(line,&filename,&source_line);
     if(marker<0){free(line);free_lines(lines,nlines);if(in!=stdin)fclose(in);return 1;}
     if(!marker&&source_line<SIZE_MAX)source_line++;
   }
   if(ferror(in)){report_io_error(inputs[fi]);free(line);free_lines(lines,nlines);if(in!=stdin)fclose(in);return 2;}
   if(in!=stdin && fclose(in)!=0){report_io_error(inputs[fi]);free(line);free_lines(lines,nlines);return 2;}
 }
 free(line);
 if(!preprocess_macros(&lines,&nlines)||!normalize_numeric_labels(lines,nlines)||!collect_equations(lines,nlines)){free_lines(lines,nlines);return include_io_error?2:1;}
 short_lines=malloc(nlines?nlines:1);if(!short_lines){report_io_error("malloc");free_lines(lines,nlines);return 1;}
 memset(short_lines,1,nlines);
 /* Begin with short branches and monotonically widen those that do not fit. */
 size_t max_passes=sizeof branches/sizeof branches[0]+1;
 for(size_t pass=0;pass<max_passes;pass++){
   reset_assembly_state();
   load_equations();
   for(current_line=0;current_line<nlines&&!failed;current_line++){current_location=lines[current_line].location;char *copy=strdup(lines[current_line].text);if(!copy){err("out of memory");break;}assemble(copy);free(copy);}
   if(!failed)finish_merge_sections();
   if(!failed)finish_common_allocations();
   if(failed)break;
   int changed=0;resolve_branches(1,&changed,lines);
   if(!changed)break;
   if(pass+1==max_passes)err("branch relaxation did not converge");
 }
 if(!failed){
   reset_assembly_state();
   report_warnings=1;
   load_equations();
   for(current_line=0;current_line<nlines&&!failed;current_line++){current_location=lines[current_line].location;char *copy=strdup(lines[current_line].text);if(!copy){err("out of memory");break;}assemble(copy);free(copy);}
   if(!failed)finish_merge_sections();
   if(!failed)finish_common_allocations();
   if(!failed){int ignored=0;resolve_branches(0,&ignored,lines);resolve_differences();resolve_symvers();if(section_stack_depth){current_location=section_stack_locations[section_stack_depth-1];err("unclosed .pushsection (missing .popsection)");}}
 }
 free_lines(lines,nlines);free(short_lines);short_lines=NULL;
 current_location=NULL;
 for(size_t i=0;i<nequs;i++){free(equs[i].name);free(equs[i].expr);} nequs=0;
 for(size_t i=0;i<nsymvers;i++){free(symvers[i].source);free(symvers[i].alias);} nsymvers=0;
 if(failed)return 1;
 for(size_t i=0;i<nsection_groups;i++){
  Sym *sym=find_symbol(section_groups[i].signature);
  if(!sym){err("internal section group signature error");return 1;}
  int referenced=0;
  for(size_t j=0;j<nr;j++)if(!strcmp(sym->name,rels[j].sym)){referenced=1;break;}
  if(!sym->defined&&sym->bind!=STB_GLOBAL&&!referenced){
   sym->bind=STB_LOCAL;sym->defined=1;sym->signature_group=(int)i+1;
  }
 }
 size_t kept=0;
 for(size_t i=0;i<ns;i++){
  int referenced=0;
  if(!syms[i]->defined&&syms[i]->bind==STB_WEAK){
   for(size_t j=0;j<nr;j++)if(!strcmp(syms[i]->name,rels[j].sym)){referenced=1;break;}
   if(!referenced){free(syms[i]->name);free(syms[i]);continue;}
  }
  syms[kept++]=syms[i];
 }
 ns=kept;
 if(symbol_bucket_count)memset(symbol_buckets,0,symbol_bucket_count*sizeof *symbol_buckets);
 for(size_t i=0;i<ns;i++){
  size_t slot=symbol_hash(syms[i]->name)%symbol_bucket_count;
  syms[i]->next=symbol_buckets[slot];symbol_buckets[slot]=syms[i];
 }
 unsigned char shstr[1<<16]={0};size_t st=1,sht=1;
 if(nfile_symbols>UINT32_MAX-1-ns){err("too many symbols");return 1;}
 for(size_t i=0;i<nfile_symbols;i++){
  size_t z=strlen(file_symbols[i])+1;
  if(z>UINT32_MAX-st){err("string table too large");return 1;}
  st+=z;
 }
 for(size_t i=0;i<ns;i++){
  size_t z=strlen(syms[i]->name)+1;
  if(z>UINT32_MAX-st){err("string table too large");return 1;}
  syms[i]->name_offset=(uint32_t)st;st+=z;
 }
 for(size_t i=0;i<ns;i++)if((!syms[i]->defined||syms[i]->section==SHN_COMMON)&&syms[i]->bind==STB_LOCAL)syms[i]->bind=STB_GLOBAL;
 size_t locals=nfile_symbols;for(size_t i=0;i<ns;i++)if(syms[i]->bind==STB_LOCAL)locals++;
 size_t symbol_count=ns+nfile_symbols;
 size_t target_count=4+ncustom_sections;
 size_t *rel_count=calloc(target_count+1,sizeof *rel_count);
 if(!rel_count){err("out of memory building ELF relocations");return 1;}
 for(size_t i=0;i<nr;i++){int sec=rels[i].section;if(sec<1||sec>(int)target_count){err("relocation refers to invalid section");continue;}if(section_is_nobits(sec)){err("relocations in NOBITS sections are invalid");continue;}rel_count[sec]++;}
 if(failed){free(rel_count);return 1;}
 size_t rela_count=0;for(size_t sec=1;sec<=target_count;sec++)if(rel_count[sec])rela_count++;
 size_t symtab_idx=1+nsection_groups+target_count+rela_count, strtab_idx=symtab_idx+1, shstr_idx=symtab_idx+2, shnum=shstr_idx+1;
 Elf64_Shdr *sh=calloc(shnum,sizeof *sh);uint32_t *target_names=calloc(target_count+1,sizeof *target_names),*rela_names=calloc(target_count+1,sizeof *rela_names);
 if(!sh||!target_names||!rela_names){err("out of memory building ELF sections");free(rel_count);free(sh);free(target_names);free(rela_names);return 1;}
 uint32_t rel_indexes[MAX_CUSTOM_SECTIONS+5]={0};
 uint32_t group_entries[MAX_CUSTOM_SECTIONS*(1+2*MAX_CUSTOM_SECTIONS)]={0};
 size_t group_sizes[MAX_CUSTOM_SECTIONS]={0};
 for(size_t i=0;i<nsection_groups;i++){
   uint32_t groupname=(uint32_t)sht;memcpy(shstr+sht,".group",sizeof ".group");sht+=sizeof ".group";
   sh[i+1]=(Elf64_Shdr){.sh_name=groupname,.sh_type=SHT_GROUP,.sh_link=(uint32_t)symtab_idx,.sh_addralign=4,.sh_entsize=4};
   group_entries[i*(1+2*MAX_CUSTOM_SECTIONS)+group_sizes[i]++]=section_groups[i].comdat?GRP_COMDAT:0;
 }
 const char *base_names[]={NULL,".text",".data",".bss",".rodata"};
 for(size_t sec=1;sec<=target_count;sec++){
   const char *nm=sec<=4?base_names[sec]:custom_sections[sec-5].name;
   target_names[sec]=(uint32_t)sht;size_t z=strlen(nm)+1;if(sht+z>=sizeof shstr){err("section string table too large");break;}memcpy(shstr+sht,nm,z);sht+=z;
   sh[nsection_groups+sec]=(Elf64_Shdr){.sh_name=target_names[sec],.sh_type=section_type((int)sec),.sh_flags=section_flags((int)sec),.sh_addralign=section_align((int)sec),.sh_entsize=sec>=5?custom_sections[sec-5].entsize:0,.sh_size=sec==1?nt:sec==2?nd:sec==3?nb:sec==4?nro:custom_sections[sec-5].size};
 }
 size_t next_rela=nsection_groups+target_count;
 for(size_t sec=1;sec<=target_count;sec++)if(rel_count[sec]){
   char rname[160];snprintf(rname,sizeof rname,".rela%s",section_name((int)sec));rela_names[sec]=(uint32_t)sht;size_t z=strlen(rname)+1;if(sht+z>=sizeof shstr){err("section string table too large");break;}memcpy(shstr+sht,rname,z);sht+=z;
   rel_indexes[sec]=(uint32_t)++next_rela;
   sh[next_rela]=(Elf64_Shdr){.sh_name=rela_names[sec],.sh_type=SHT_RELA,.sh_flags=SHF_INFO_LINK|(section_flags((int)sec)&SHF_GROUP),.sh_link=(uint32_t)symtab_idx,.sh_info=(uint32_t)(nsection_groups+sec),.sh_addralign=8,.sh_entsize=sizeof(Elf64_Rela),.sh_size=rel_count[sec]*sizeof(Elf64_Rela)};
 }
 for(size_t sec=5;sec<=target_count;sec++)if(custom_sections[sec-5].group){
   size_t g=(size_t)custom_sections[sec-5].group-1;
   group_entries[g*(1+2*MAX_CUSTOM_SECTIONS)+group_sizes[g]++]=(uint32_t)(nsection_groups+sec);
   if(rel_indexes[sec])group_entries[g*(1+2*MAX_CUSTOM_SECTIONS)+group_sizes[g]++]=rel_indexes[sec];
 }
 for(size_t i=0;i<nsection_groups;i++)sh[i+1].sh_size=group_sizes[i]*sizeof(uint32_t);
 uint32_t symname=(uint32_t)sht;memcpy(shstr+sht,".symtab",8);sht+=8;
 uint32_t strname=(uint32_t)sht;memcpy(shstr+sht,".strtab",8);sht+=8;
 uint32_t shstrname=(uint32_t)sht;memcpy(shstr+sht,".shstrtab",sizeof ".shstrtab");sht+=sizeof ".shstrtab";
 sh[symtab_idx]=(Elf64_Shdr){.sh_name=symname,.sh_type=SHT_SYMTAB,.sh_link=(uint32_t)strtab_idx,.sh_info=(uint32_t)(1+locals),.sh_addralign=8,.sh_entsize=sizeof(Elf64_Sym),.sh_size=(symbol_count+1)*sizeof(Elf64_Sym)};
 sh[strtab_idx]=(Elf64_Shdr){.sh_name=strname,.sh_type=SHT_STRTAB,.sh_addralign=1,.sh_size=st};
 sh[shstr_idx]=(Elf64_Shdr){.sh_name=shstrname,.sh_type=SHT_STRTAB,.sh_addralign=1,.sh_size=sht};
 /* Rebuild the section-name table in section-index order. */
 memset(shstr,0,sizeof shstr);sht=1;
 for(size_t i=0;i<nsection_groups;i++){sh[i+1].sh_name=(uint32_t)sht;memcpy(shstr+sht,".group",sizeof ".group");sht+=sizeof ".group";}
 for(size_t sec=1;sec<=target_count;sec++){const char *nm=section_name((int)sec);size_t z=strlen(nm)+1;sh[nsection_groups+sec].sh_name=(uint32_t)sht;memcpy(shstr+sht,nm,z);sht+=z;}
 size_t rela_idx=nsection_groups+target_count;
 for(size_t sec=1;sec<=target_count;sec++)if(rel_count[sec]){char rn[160];snprintf(rn,sizeof rn,".rela%s",section_name((int)sec));size_t z=strlen(rn)+1;sh[++rela_idx].sh_name=(uint32_t)sht;memcpy(shstr+sht,rn,z);sht+=z;}
 sh[symtab_idx].sh_name=(uint32_t)sht;memcpy(shstr+sht,".symtab",8);sht+=8;
 sh[strtab_idx].sh_name=(uint32_t)sht;memcpy(shstr+sht,".strtab",8);sht+=8;
 sh[shstr_idx].sh_name=(uint32_t)sht;memcpy(shstr+sht,".shstrtab",sizeof ".shstrtab");sht+=sizeof ".shstrtab";sh[shstr_idx].sh_size=sht;
 Elf64_Sym *es=calloc(symbol_count+1,sizeof *es);size_t *order=calloc(ns?ns:1,sizeof *order);size_t oi=0;
 if(!es||!order){err("out of memory building ELF symbols");free(es);free(order);free(rel_count);free(target_names);free(rela_names);free(sh);return 1;}
 for(size_t i=0;i<ns;i++)if(syms[i]->bind==STB_LOCAL)order[oi++]=i;
 for(size_t i=0;i<ns;i++)if(syms[i]->bind!=STB_LOCAL)order[oi++]=i;
 size_t file_offset=1,file_index=0,elf_index=1;
 for(size_t i=0;i<ns;i++){
  Sym *s=syms[order[i]];
  while(file_index<nfile_symbols &&
        (s->bind!=STB_LOCAL||file_index==0||file_index<s->file_count)){
   es[elf_index].st_name=(uint32_t)file_offset;
   es[elf_index].st_info=ELF64_ST_INFO(STB_LOCAL,STT_FILE);
   es[elf_index++].st_shndx=SHN_ABS;
   file_offset+=strlen(file_symbols[file_index++])+1;
  }
  write_elf_symbol(&es[elf_index],s,(uint32_t)elf_index);
  elf_index++;
 }
 while(file_index<nfile_symbols){
  es[elf_index].st_name=(uint32_t)file_offset;
  es[elf_index].st_info=ELF64_ST_INFO(STB_LOCAL,STT_FILE);
  es[elf_index++].st_shndx=SHN_ABS;
  file_offset+=strlen(file_symbols[file_index++])+1;
 }
 for(size_t g=0;g<nsection_groups;g++){
  Sym *sym=find_symbol(section_groups[g].signature);
  if(!sym){err("internal section group signature error");break;}
  sh[g+1].sh_info=sym->elf_index;
 }
 Elf64_Rela **rel_arrays=calloc(target_count+1,sizeof *rel_arrays);size_t *rel_used=calloc(target_count+1,sizeof *rel_used);
 if(!rel_arrays||!rel_used)err("out of memory building ELF relocations");
 if(!failed)for(size_t sec=1;sec<=target_count;sec++)if(rel_count[sec]){
  rel_arrays[sec]=calloc(rel_count[sec],sizeof(Elf64_Rela));
  if(!rel_arrays[sec]){err("out of memory building ELF relocations");break;}
 }
 if(!failed)for(size_t i=0;i<nr;i++){int sec=rels[i].section;Sym *sym=find_symbol(rels[i].sym);if(!sym){err("internal relocation symbol error");continue;}Elf64_Rela r=rels[i].r;r.r_info=ELF64_R_INFO(sym->elf_index,ELF64_R_TYPE(r.r_info));rel_arrays[sec][rel_used[sec]++]=r;}
 unsigned char *str=failed?NULL:malloc(st);
 if(!failed&&!str)err("out of memory building ELF strings");
 if(failed){
  if(rel_arrays)for(size_t sec=1;sec<=target_count;sec++)free(rel_arrays[sec]);
  free(rel_arrays);free(rel_used);free(rel_count);free(target_names);free(rela_names);free(sh);free(es);free(order);return 1;
 }
 str[0]=0;
 file_offset=1;
 for(size_t i=0;i<nfile_symbols;i++){size_t z=strlen(file_symbols[i])+1;memcpy(str+file_offset,file_symbols[i],z);file_offset+=z;}
 for(size_t i=0;i<ns;i++)memcpy(str+syms[i]->name_offset,syms[i]->name,strlen(syms[i]->name)+1);
 Elf64_Ehdr eh={0};memcpy(eh.e_ident,ELFMAG,SELFMAG);eh.e_ident[EI_CLASS]=ELFCLASS64;eh.e_ident[EI_DATA]=ELFDATA2LSB;eh.e_ident[EI_VERSION]=EV_CURRENT;eh.e_ident[EI_OSABI]=ELFOSABI_SYSV;eh.e_type=ET_REL;eh.e_machine=EM_X86_64;eh.e_version=EV_CURRENT;eh.e_ehsize=sizeof eh;eh.e_shentsize=sizeof(Elf64_Shdr);eh.e_shnum=(uint16_t)shnum;eh.e_shstrndx=(uint16_t)shstr_idx;
 FILE *out=fopen(output,"wb");if(!out){report_io_error(output);for(size_t sec=1;sec<=target_count;sec++)free(rel_arrays[sec]);free(str);free(rel_arrays);free(rel_used);free(rel_count);free(target_names);free(rela_names);free(sh);free(es);free(order);return 2;}fwrite(&eh,sizeof eh,1,out);long off=(long)sizeof eh;
 #define PAD(a) while(off%(long)(a)){fputc(0,out);off++;}
 for(size_t g=0;g<nsection_groups;g++){PAD(4);sh[g+1].sh_offset=(uint64_t)off;fwrite(&group_entries[g*(1+2*MAX_CUSTOM_SECTIONS)],sizeof(uint32_t),group_sizes[g],out);off+=(long)(group_sizes[g]*sizeof(uint32_t));}
 for(size_t sec=1;sec<=target_count;sec++){
   size_t al=section_align((int)sec);if(!al)al=1;PAD(al);sh[nsection_groups+sec].sh_offset=(uint64_t)off;
   if(section_type((int)sec)!=SHT_NOBITS){unsigned char *buf=sec==1?text:sec==2?data:sec==4?rodata:sec>=5?custom_sections[sec-5].data:NULL;size_t sz=(size_t)sh[nsection_groups+sec].sh_size;if(sz&&buf)fwrite(buf,1,sz,out);off+=(long)sz;}
 }
 size_t ri=nsection_groups+target_count;
 for(size_t sec=1;sec<=target_count;sec++)if(rel_count[sec]){PAD(8);sh[++ri].sh_offset=(uint64_t)off;fwrite(rel_arrays[sec],sizeof(Elf64_Rela),rel_count[sec],out);off+=(long)(rel_count[sec]*sizeof(Elf64_Rela));}
 PAD(8);sh[symtab_idx].sh_offset=(uint64_t)off;fwrite(es,sizeof *es,symbol_count+1,out);off+=(long)((symbol_count+1)*sizeof *es);
 sh[strtab_idx].sh_offset=(uint64_t)off;fwrite(str,1,st,out);off+=(long)st;sh[shstr_idx].sh_offset=(uint64_t)off;fwrite(shstr,1,sht,out);off+=(long)sht;
 PAD(8);eh.e_shoff=(uint64_t)off;
 int io_error=ferror(out);
 if(fseek(out,0,SEEK_SET)!=0)io_error=1;
 if(fwrite(&eh,sizeof eh,1,out)!=1)io_error=1;
 if(fseek(out,(long)eh.e_shoff,SEEK_SET)!=0)io_error=1;
 if(fwrite(sh,sizeof *sh,shnum,out)!=shnum)io_error=1;
 if(fclose(out)!=0)io_error=1;
 if(io_error)fprintf(stderr,"crunch-as: failed to write object '%s'\n",output);
 for(size_t sec=1;sec<=target_count;sec++){free(rel_arrays[sec]);}
 free(str);free(rel_arrays);free(rel_used);free(rel_count);free(target_names);free(rela_names);free(sh);free(es);free(order);return io_error?2:0;
}

/**
 * @brief Assembles files with additional include directories into an ELF64 object.
 * @param inputs Input paths; "-" reads standard input.
 * @param count Number of input paths.
 * @param output Object output path.
 * @param include_dirs Include directories searched after the working directory.
 * @param include_count Number of include directories.
 * @return Compiler status; diagnostics are currently emitted to standard error.
 */
CompilerStatus crunch_assemble_files_with_includes(const char *const *inputs,size_t count,
                                                    const char *output,
                                                    const char *const *include_dirs,
                                                    size_t include_count){
 if(!inputs||!count||!output||!*output)return COMPILER_INVALID_INPUT;
 for(size_t i=0;i<count;i++)if(!inputs[i]||!*inputs[i])return COMPILER_INVALID_INPUT;
 if(include_count&&!include_dirs)return COMPILER_INVALID_INPUT;
 for(size_t i=0;i<include_count;i++)if(!include_dirs[i]||!*include_dirs[i])return COMPILER_INVALID_INPUT;
 assembler_include_dirs=include_dirs;assembler_include_count=include_count;include_io_error=0;
 reset_assembly_state();nlines=0;nmacros=0;macro_unique=0;
 int result=assemble_files(inputs,count,output);
 reset_assembly_state();
 for(size_t i=0;i<nequs;i++){free(equs[i].name);free(equs[i].expr);}nequs=0;
 for(size_t i=0;i<nmacros;i++){
   free(macros[i].name);
   for(size_t j=0;j<macros[i].np;j++){free(macros[i].params[j]);free(macros[i].defaults[j]);}
   for(size_t j=0;j<macros[i].nb;j++)free(macros[i].body[j].text);
   free(macros[i].body);
 }
 nmacros=0;nlines=0;
 free(short_lines);short_lines=NULL;
 current_location=NULL;
 while(allocated_locations){SourceLocationNode *next=allocated_locations->allocated_next;free(allocated_locations);allocated_locations=next;}
 while(allocated_filenames){SourceFilename *next=allocated_filenames->next;free(allocated_filenames->name);free(allocated_filenames);allocated_filenames=next;}
 assembler_include_dirs=NULL;assembler_include_count=0;include_io_error=0;
 return result==2?COMPILER_IO_ERROR:result?COMPILER_CODEGEN_ERROR:COMPILER_OK;
}

/**
 * @brief Assembles one or more files without additional include directories.
 * @param inputs Input paths; "-" reads standard input.
 * @param count Number of input paths.
 * @param output Object output path.
 * @return Compiler status; diagnostics are currently emitted to standard error.
 */
CompilerStatus crunch_assemble_files(const char *const *inputs,size_t count,const char *output){
 return crunch_assemble_files_with_includes(inputs,count,output,NULL,0);
}
