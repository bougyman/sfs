/* A Bison parser, made by GNU Bison 1.875a.  */

/* Skeleton parser for Yacc-like parsing with Bison,
   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* Written by Richard Stallman by simplifying the original so called
   ``semantic'' parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Using locations.  */
#define YYLSP_NEEDED 0



/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     T_ID = 258,
     T_NUM = 259,
     T_CONST = 260,
     T_STRUCT = 261,
     T_UNION = 262,
     T_ENUM = 263,
     T_TYPEDEF = 264,
     T_PROGRAM = 265,
     T_UNSIGNED = 266,
     T_INT = 267,
     T_HYPER = 268,
     T_DOUBLE = 269,
     T_QUADRUPLE = 270,
     T_VOID = 271,
     T_VERSION = 272,
     T_SWITCH = 273,
     T_CASE = 274,
     T_DEFAULT = 275,
     T_OPAQUE = 276,
     T_STRING = 277
   };
#endif
#define T_ID 258
#define T_NUM 259
#define T_CONST 260
#define T_STRUCT 261
#define T_UNION 262
#define T_ENUM 263
#define T_TYPEDEF 264
#define T_PROGRAM 265
#define T_UNSIGNED 266
#define T_INT 267
#define T_HYPER 268
#define T_DOUBLE 269
#define T_QUADRUPLE 270
#define T_VOID 271
#define T_VERSION 272
#define T_SWITCH 273
#define T_CASE 274
#define T_DEFAULT 275
#define T_OPAQUE 276
#define T_STRING 277




/* Copy the first part of user declarations.  */
#line 24 "./parse.yy"

#include "rpcc.h"
#define YYSTYPE YYSTYPE

static int proc_compare (const void *, const void *);
static int vers_compare (const void *, const void *);
static str getnewid (str);
static str getid (str);


/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

#if ! defined (YYSTYPE) && ! defined (YYSTYPE_IS_DECLARED)
typedef int YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



/* Copy the second part of user declarations.  */


/* Line 214 of yacc.c.  */
#line 141 "y.tab.c"

#if ! defined (yyoverflow) || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# if YYSTACK_USE_ALLOCA
#  define YYSTACK_ALLOC alloca
# else
#  ifndef YYSTACK_USE_ALLOCA
#   if defined (alloca) || defined (_ALLOCA_H)
#    define YYSTACK_ALLOC alloca
#   else
#    ifdef __GNUC__
#     define YYSTACK_ALLOC __builtin_alloca
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning. */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
# else
#  if defined (__STDC__) || defined (__cplusplus)
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   define YYSIZE_T size_t
#  endif
#  define YYSTACK_ALLOC malloc
#  define YYSTACK_FREE free
# endif
#endif /* ! defined (yyoverflow) || YYERROR_VERBOSE */


#if (! defined (yyoverflow) \
     && (! defined (__cplusplus) \
	 || (YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
struct yyalloc
{
  short yyss;
  YYSTYPE yyvs;
  };

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (struct yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (short) + sizeof (YYSTYPE))				\
      + YYSTACK_GAP_MAXIMUM)

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  register YYSIZE_T yyi;		\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (0)
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack)					\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack, Stack, yysize);				\
	Stack = &yyptr->Stack;						\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (0)

#endif

#if defined (__STDC__) || defined (__cplusplus)
   typedef signed char yysigned_char;
#else
   typedef short yysigned_char;
#endif

/* YYFINAL -- State number of the termination state. */
#define YYFINAL  2
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   180

/* YYNTOKENS -- Number of terminals. */
#define YYNTOKENS  36
/* YYNNTS -- Number of nonterminals. */
#define YYNNTS  38
/* YYNRULES -- Number of rules. */
#define YYNRULES  74
/* YYNRULES -- Number of states. */
#define YYNSTATES  154

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   277

#define YYTRANSLATE(YYX) 						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const unsigned char yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
      28,    29,    31,     2,    27,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    30,    24,
      34,    23,    35,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    32,     2,    33,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    25,     2,    26,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const unsigned char yyprhs[] =
{
       0,     0,     3,     4,     5,     9,    11,    13,    15,    17,
      19,    21,    24,    28,    34,    35,    44,    45,    47,    48,
      56,    57,    70,    71,    81,    83,    86,    87,    97,    99,
     102,   111,   113,   116,   119,   121,   124,   128,   131,   133,
     136,   138,   141,   143,   145,   149,   151,   155,   157,   161,
     165,   170,   177,   184,   191,   198,   205,   211,   217,   223,
     225,   227,   229,   231,   233,   235,   238,   240,   243,   245,
     247,   249,   251,   253,   255
};

/* YYRHS -- A `-1'-separated list of the rules' RHS. */
static const yysigned_char yyrhs[] =
{
      37,     0,    -1,    -1,    -1,    37,    38,    39,    -1,    41,
      -1,    42,    -1,    45,    -1,    40,    -1,    47,    -1,    49,
      -1,     9,    66,    -1,     9,     6,    66,    -1,     5,    72,
      23,    70,    24,    -1,    -1,     8,    72,    25,    43,    63,
      44,    26,    24,    -1,    -1,    27,    -1,    -1,     6,    72,
      25,    46,    61,    26,    24,    -1,    -1,     7,    72,    18,
      28,    68,     3,    29,    25,    48,    56,    26,    24,    -1,
      -1,    10,    72,    25,    50,    51,    26,    23,    71,    24,
      -1,    52,    -1,    51,    52,    -1,    -1,    17,    72,    25,
      53,    54,    26,    23,    71,    24,    -1,    55,    -1,    54,
      55,    -1,    67,    72,    28,    67,    29,    23,    71,    24,
      -1,    57,    -1,    56,    57,    -1,    58,    60,    -1,    59,
      -1,    58,    59,    -1,    19,    70,    30,    -1,    20,    30,
      -1,    66,    -1,    16,    24,    -1,    62,    -1,    61,    62,
      -1,    66,    -1,    64,    -1,    63,    27,    64,    -1,    65,
      -1,    72,    23,    70,    -1,    72,    -1,    68,     3,    24,
      -1,    22,     3,    24,    -1,    68,    31,     3,    24,    -1,
      68,     3,    32,    70,    33,    24,    -1,    21,     3,    32,
      70,    33,    24,    -1,    68,     3,    34,    70,    35,    24,
      -1,    22,     3,    34,    70,    35,    24,    -1,    21,     3,
      34,    70,    35,    24,    -1,    68,     3,    34,    35,    24,
      -1,    22,     3,    34,    35,    24,    -1,    21,     3,    34,
      35,    24,    -1,    68,    -1,    16,    -1,    69,    -1,    73,
      -1,    11,    -1,    12,    -1,    11,    12,    -1,    13,    -1,
      11,    13,    -1,    14,    -1,    15,    -1,    73,    -1,     4,
      -1,     4,    -1,     3,    -1,     3,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const unsigned short yyrline[] =
{
       0,    65,    65,    66,    66,    69,    70,    71,    72,    73,
      74,    77,    84,    94,   104,   103,   112,   113,   117,   116,
     126,   125,   137,   136,   151,   151,   155,   154,   170,   170,
     173,   185,   185,   188,   191,   191,   194,   201,   209,   216,
     226,   226,   229,   233,   234,   237,   241,   242,   245,   247,
     252,   254,   257,   260,   262,   264,   266,   269,   272,   277,
     277,   280,   280,   283,   284,   285,   286,   287,   288,   289,
     292,   292,   295,   298,   301
};
#endif

#if YYDEBUG || YYERROR_VERBOSE
/* YYTNME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals. */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "T_ID", "T_NUM", "T_CONST", "T_STRUCT", 
  "T_UNION", "T_ENUM", "T_TYPEDEF", "T_PROGRAM", "T_UNSIGNED", "T_INT", 
  "T_HYPER", "T_DOUBLE", "T_QUADRUPLE", "T_VOID", "T_VERSION", "T_SWITCH", 
  "T_CASE", "T_DEFAULT", "T_OPAQUE", "T_STRING", "'='", "';'", "'{'", 
  "'}'", "','", "'('", "')'", "':'", "'*'", "'['", "']'", "'<'", "'>'", 
  "$accept", "file", "@1", "definition", "def_type", "def_const", 
  "def_enum", "@2", "comma_warn", "def_struct", "@3", "def_union", "@4", 
  "def_program", "@5", "version_list", "version_decl", "@6", "proc_list", 
  "proc_decl", "union_taglist", "union_tag", "union_caselist", 
  "union_case", "union_decl", "struct_decllist", "struct_decl", 
  "enum_taglist", "enum_tag", "enum_cnstag", "declaration", 
  "type_or_void", "type", "base_type", "value", "number", "newid", "id", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const unsigned short yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,    61,    59,   123,   125,    44,    40,    41,
      58,    42,    91,    93,    60,    62
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const unsigned char yyr1[] =
{
       0,    36,    37,    38,    37,    39,    39,    39,    39,    39,
      39,    40,    40,    41,    43,    42,    44,    44,    46,    45,
      48,    47,    50,    49,    51,    51,    53,    52,    54,    54,
      55,    56,    56,    57,    58,    58,    59,    59,    60,    60,
      61,    61,    62,    63,    63,    64,    65,    65,    66,    66,
      66,    66,    66,    66,    66,    66,    66,    66,    66,    67,
      67,    68,    68,    69,    69,    69,    69,    69,    69,    69,
      70,    70,    71,    72,    73
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const unsigned char yyr2[] =
{
       0,     2,     0,     0,     3,     1,     1,     1,     1,     1,
       1,     2,     3,     5,     0,     8,     0,     1,     0,     7,
       0,    12,     0,     9,     1,     2,     0,     9,     1,     2,
       8,     1,     2,     2,     1,     2,     3,     2,     1,     2,
       1,     2,     1,     1,     3,     1,     3,     1,     3,     3,
       4,     6,     6,     6,     6,     6,     5,     5,     5,     1,
       1,     1,     1,     1,     1,     2,     1,     2,     1,     1,
       1,     1,     1,     1,     1
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const unsigned char yydefact[] =
{
       2,     3,     1,     0,     0,     0,     0,     0,     0,     0,
       4,     8,     5,     6,     7,     9,    10,    73,     0,     0,
       0,     0,    74,     0,    63,    64,    66,    68,    69,     0,
       0,    11,     0,    61,    62,     0,     0,    18,     0,    14,
      12,    65,    67,     0,     0,     0,     0,    22,    71,     0,
      70,     0,     0,     0,     0,     0,    49,     0,    48,     0,
       0,     0,     0,    13,     0,    40,    42,     0,    16,    43,
      45,    47,     0,     0,     0,     0,     0,     0,     0,     0,
      50,     0,     0,    24,     0,    41,     0,    17,     0,     0,
       0,    58,     0,    57,     0,     0,    56,     0,     0,     0,
      25,    19,     0,    44,     0,    46,    52,    55,    54,    51,
      53,    26,     0,    20,    15,     0,    72,     0,     0,    60,
       0,    28,     0,    59,    23,     0,     0,     0,    31,     0,
      34,     0,    29,     0,     0,    37,     0,    32,     0,    35,
      33,    38,     0,     0,    36,    21,    39,     0,     0,    27,
       0,     0,     0,    30
};

/* YYDEFGOTO[NTERM-NUM]. */
static const short yydefgoto[] =
{
      -1,     1,     3,    10,    11,    12,    13,    53,    88,    14,
      51,    15,   118,    16,    62,    82,    83,   115,   120,   121,
     127,   128,   129,   130,   140,    64,    65,    68,    69,    70,
      66,   122,    32,    33,    49,   117,    71,    34
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -98
static const short yypact[] =
{
     -98,    22,   -98,   149,    27,    27,    27,    27,   111,    27,
     -98,   -98,   -98,   -98,   -98,   -98,   -98,   -98,     2,    18,
      42,    39,   -98,   124,    36,   -98,   -98,   -98,   -98,    64,
      71,   -98,     4,   -98,   -98,    54,    68,   -98,    52,   -98,
     -98,   -98,   -98,    19,   -11,    10,    78,   -98,   -98,    65,
     -98,   124,    25,    27,    68,     6,   -98,    15,   -98,    68,
      17,    66,    75,   -98,    44,   -98,   -98,    90,    67,   -98,
     -98,    82,    62,    87,    77,    89,    80,    73,    92,    83,
     -98,    27,     7,   -98,    96,   -98,    99,    27,   103,    68,
     106,   -98,   107,   -98,   110,   117,   -98,   118,   119,   120,
     -98,   -98,   122,   -98,   136,   -98,   -98,   -98,   -98,   -98,
     -98,   -98,   157,   -98,   -98,   137,   -98,   138,    57,   -98,
      72,   -98,    27,   -98,   -98,    68,   133,    43,   -98,    88,
     -98,   141,   -98,   139,   135,   -98,   142,   -98,   144,   -98,
     -98,   -98,   157,   137,   -98,   -98,   -98,   145,   143,   -98,
     147,   157,   150,   -98
};

/* YYPGOTO[NTERM-NUM].  */
static const yysigned_char yypgoto[] =
{
     -98,   -98,   -98,   -98,   -98,   -98,   -98,   -98,   -98,   -98,
     -98,   -98,   -98,   -98,   -98,   -98,    91,   -98,   -98,    51,
     -98,    48,   -98,    47,   -98,   -98,   113,   -98,    93,   -98,
      -8,    35,   -47,   -98,   -43,   -97,    -3,   -28
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -1
static const unsigned char yytable[] =
{
      31,    18,    19,    20,    21,    67,    35,    45,    50,    22,
      48,    72,    74,    56,    76,    40,    77,    79,    22,    48,
      22,    48,     2,    57,    81,    36,    50,    50,    22,    50,
      17,    50,    50,    99,    58,    46,    24,    25,    26,    27,
      28,    73,    59,    37,    60,   147,   105,    22,    41,    42,
      75,    54,    78,    55,   152,    24,    25,    26,    27,    28,
      38,    50,   125,   126,    39,    29,    30,    43,   123,   136,
      84,    22,    48,   123,    44,    22,   125,   126,    98,    47,
      52,    61,   134,    24,    25,    26,    27,    28,   119,    63,
      80,    22,    81,    86,    87,    90,   123,    50,   131,    24,
      25,    26,    27,    28,   138,    89,    95,   125,   126,    29,
      30,    91,    92,    93,    22,    94,    96,    23,    97,   133,
     101,   141,    24,    25,    26,    27,    28,    22,   102,   104,
     106,   107,    29,    30,   108,    24,    25,    26,    27,    28,
      22,   109,   110,   112,   111,    29,    30,   113,    24,    25,
      26,    27,    28,   119,     4,     5,     6,     7,     8,     9,
     114,   116,   124,   135,   142,   144,   145,   143,   146,   149,
     151,   132,   150,   100,   153,   137,   139,    85,   148,     0,
     103
};

static const short yycheck[] =
{
       8,     4,     5,     6,     7,    52,     9,     3,    36,     3,
       4,    54,    55,    24,    57,    23,    59,    60,     3,     4,
       3,     4,     0,    34,    17,    23,    54,    55,     3,    57,
       3,    59,    60,    26,    24,    31,    11,    12,    13,    14,
      15,    35,    32,    25,    34,   142,    89,     3,    12,    13,
      35,    32,    35,    34,   151,    11,    12,    13,    14,    15,
      18,    89,    19,    20,    25,    21,    22,     3,   115,    26,
      26,     3,     4,   120,     3,     3,    19,    20,    81,    25,
      28,     3,   125,    11,    12,    13,    14,    15,    16,    24,
      24,     3,    17,     3,    27,    33,   143,   125,    26,    11,
      12,    13,    14,    15,    16,    23,    33,    19,    20,    21,
      22,    24,    35,    24,     3,    35,    24,     6,    35,   122,
      24,   129,    11,    12,    13,    14,    15,     3,    29,    26,
      24,    24,    21,    22,    24,    11,    12,    13,    14,    15,
       3,    24,    24,    23,    25,    21,    22,    25,    11,    12,
      13,    14,    15,    16,     5,     6,     7,     8,     9,    10,
      24,     4,    24,    30,    23,    30,    24,    28,    24,    24,
      23,   120,    29,    82,    24,   127,   129,    64,   143,    -1,
      87
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const unsigned char yystos[] =
{
       0,    37,     0,    38,     5,     6,     7,     8,     9,    10,
      39,    40,    41,    42,    45,    47,    49,     3,    72,    72,
      72,    72,     3,     6,    11,    12,    13,    14,    15,    21,
      22,    66,    68,    69,    73,    72,    23,    25,    18,    25,
      66,    12,    13,     3,     3,     3,    31,    25,     4,    70,
      73,    46,    28,    43,    32,    34,    24,    34,    24,    32,
      34,     3,    50,    24,    61,    62,    66,    68,    63,    64,
      65,    72,    70,    35,    70,    35,    70,    70,    35,    70,
      24,    17,    51,    52,    26,    62,     3,    27,    44,    23,
      33,    24,    35,    24,    35,    33,    24,    35,    72,    26,
      52,    24,    29,    64,    26,    70,    24,    24,    24,    24,
      24,    25,    23,    25,    24,    53,     4,    71,    48,    16,
      54,    55,    67,    68,    24,    19,    20,    56,    57,    58,
      59,    26,    55,    72,    70,    30,    26,    57,    16,    59,
      60,    66,    23,    28,    30,    24,    24,    71,    67,    24,
      29,    23,    71,    24
};

#if ! defined (YYSIZE_T) && defined (__SIZE_TYPE__)
# define YYSIZE_T __SIZE_TYPE__
#endif
#if ! defined (YYSIZE_T) && defined (size_t)
# define YYSIZE_T size_t
#endif
#if ! defined (YYSIZE_T)
# if defined (__STDC__) || defined (__cplusplus)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# endif
#endif
#if ! defined (YYSIZE_T)
# define YYSIZE_T unsigned int
#endif

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrlab1


/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */

#define YYFAIL		goto yyerrlab

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yytoken = YYTRANSLATE (yychar);				\
      YYPOPSTACK;						\
      goto yybackup;						\
    }								\
  else								\
    { 								\
      yyerror ("syntax error: cannot back up");\
      YYERROR;							\
    }								\
while (0)

#define YYTERROR	1
#define YYERRCODE	256

/* YYLLOC_DEFAULT -- Compute the default location (before the actions
   are run).  */

#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)         \
  Current.first_line   = Rhs[1].first_line;      \
  Current.first_column = Rhs[1].first_column;    \
  Current.last_line    = Rhs[N].last_line;       \
  Current.last_column  = Rhs[N].last_column;
#endif

/* YYLEX -- calling `yylex' with the right arguments.  */

#ifdef YYLEX_PARAM
# define YYLEX yylex (YYLEX_PARAM)
#else
# define YYLEX yylex ()
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (0)

# define YYDSYMPRINT(Args)			\
do {						\
  if (yydebug)					\
    yysymprint Args;				\
} while (0)

# define YYDSYMPRINTF(Title, Token, Value, Location)		\
do {								\
  if (yydebug)							\
    {								\
      YYFPRINTF (stderr, "%s ", Title);				\
      yysymprint (stderr, 					\
                  Token, Value);	\
      YYFPRINTF (stderr, "\n");					\
    }								\
} while (0)

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (cinluded).                                                   |
`------------------------------------------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yy_stack_print (short *bottom, short *top)
#else
static void
yy_stack_print (bottom, top)
    short *bottom;
    short *top;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (/* Nothing. */; bottom <= top; ++bottom)
    YYFPRINTF (stderr, " %d", *bottom);
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yy_reduce_print (int yyrule)
#else
static void
yy_reduce_print (yyrule)
    int yyrule;
#endif
{
  int yyi;
  unsigned int yylineno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %u), ",
             yyrule - 1, yylineno);
  /* Print the symbols being reduced, and their result.  */
  for (yyi = yyprhs[yyrule]; 0 <= yyrhs[yyi]; yyi++)
    YYFPRINTF (stderr, "%s ", yytname [yyrhs[yyi]]);
  YYFPRINTF (stderr, "-> %s\n", yytname [yyr1[yyrule]]);
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (Rule);		\
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YYDSYMPRINT(Args)
# define YYDSYMPRINTF(Title, Token, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   SIZE_MAX < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#if YYMAXDEPTH == 0
# undef YYMAXDEPTH
#endif

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif



#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined (__GLIBC__) && defined (_STRING_H)
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
#   if defined (__STDC__) || defined (__cplusplus)
yystrlen (const char *yystr)
#   else
yystrlen (yystr)
     const char *yystr;
#   endif
{
  register const char *yys = yystr;

  while (*yys++ != '\0')
    continue;

  return yys - yystr - 1;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined (__GLIBC__) && defined (_STRING_H) && defined (_GNU_SOURCE)
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
#   if defined (__STDC__) || defined (__cplusplus)
yystpcpy (char *yydest, const char *yysrc)
#   else
yystpcpy (yydest, yysrc)
     char *yydest;
     const char *yysrc;
#   endif
{
  register char *yyd = yydest;
  register const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

#endif /* !YYERROR_VERBOSE */



#if YYDEBUG
/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yysymprint (FILE *yyoutput, int yytype, YYSTYPE *yyvaluep)
#else
static void
yysymprint (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  /* Pacify ``unused variable'' warnings.  */
  (void) yyvaluep;

  if (yytype < YYNTOKENS)
    {
      YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
# ifdef YYPRINT
      YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# endif
    }
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

  switch (yytype)
    {
      default:
        break;
    }
  YYFPRINTF (yyoutput, ")");
}

#endif /* ! YYDEBUG */
/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

#if defined (__STDC__) || defined (__cplusplus)
static void
yydestruct (int yytype, YYSTYPE *yyvaluep)
#else
static void
yydestruct (yytype, yyvaluep)
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  /* Pacify ``unused variable'' warnings.  */
  (void) yyvaluep;

  switch (yytype)
    {

      default:
        break;
    }
}


/* Prevent warnings from -Wmissing-prototypes.  */

#ifdef YYPARSE_PARAM
# if defined (__STDC__) || defined (__cplusplus)
int yyparse (void *YYPARSE_PARAM);
# else
int yyparse ();
# endif
#else /* ! YYPARSE_PARAM */
#if defined (__STDC__) || defined (__cplusplus)
int yyparse (void);
#else
int yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */



/* The lookahead symbol.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;

/* Number of syntax errors so far.  */
int yynerrs;



/*----------.
| yyparse.  |
`----------*/

#ifdef YYPARSE_PARAM
# if defined (__STDC__) || defined (__cplusplus)
int yyparse (void *YYPARSE_PARAM)
# else
int yyparse (YYPARSE_PARAM)
  void *YYPARSE_PARAM;
# endif
#else /* ! YYPARSE_PARAM */
#if defined (__STDC__) || defined (__cplusplus)
int
yyparse (void)
#else
int
yyparse ()

#endif
#endif
{
  
  register int yystate;
  register int yyn;
  int yyresult;
  /* Number of tokens to shift before error messages enabled.  */
  int yyerrstatus;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;

  /* Three stacks and their tools:
     `yyss': related to states,
     `yyvs': related to semantic values,
     `yyls': related to locations.

     Refer to the stacks thru separate pointers, to allow yyoverflow
     to reallocate them elsewhere.  */

  /* The state stack.  */
  short	yyssa[YYINITDEPTH];
  short *yyss = yyssa;
  register short *yyssp;

  /* The semantic value stack.  */
  YYSTYPE yyvsa[YYINITDEPTH];
  YYSTYPE *yyvs = yyvsa;
  register YYSTYPE *yyvsp;



#define YYPOPSTACK   (yyvsp--, yyssp--)

  YYSIZE_T yystacksize = YYINITDEPTH;

  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;


  /* When reducing, the number of symbols on the RHS of the reduced
     rule.  */
  int yylen;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss;
  yyvsp = yyvs;

  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed. so pushing a state here evens the stacks.
     */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack. Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	short *yyss1 = yyss;


	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if yyoverflow is a macro.  */
	yyoverflow ("parser stack overflow",
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),

		    &yystacksize);

	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyoverflowlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
	goto yyoverflowlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	short *yyss1 = yyss;
	struct yyalloc *yyptr =
	  (struct yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyoverflowlab;
	YYSTACK_RELOCATE (yyss);
	YYSTACK_RELOCATE (yyvs);

#  undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;


      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

/* Do appropriate processing given the current state.  */
/* Read a lookahead token if we need one and don't already have one.  */
/* yyresume: */

  /* First try to decide what to do without reference to lookahead token.  */

  yyn = yypact[yystate];
  if (yyn == YYPACT_NINF)
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YYDSYMPRINTF ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yyn == 0 || yyn == YYTABLE_NINF)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Shift the lookahead token.  */
  YYDPRINTF ((stderr, "Shifting token %s, ", yytname[yytoken]));

  /* Discard the token being shifted unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  *++yyvsp = yylval;


  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  yystate = yyn;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 2:
#line 65 "./parse.yy"
    { checkliterals (); }
    break;

  case 3:
#line 66 "./parse.yy"
    { checkliterals (); }
    break;

  case 4:
#line 66 "./parse.yy"
    { checkliterals (); }
    break;

  case 11:
#line 78 "./parse.yy"
    {
	  rpc_sym *s = &symlist.push_back ();
	  s->settype (rpc_sym::TYPEDEF);
	  *s->stypedef = yyvsp[0].decl;
	  s->stypedef->id = getnewid (s->stypedef->id);
	}
    break;

  case 12:
#line 85 "./parse.yy"
    {
	  rpc_sym *s = &symlist.push_back ();
	  s->settype (rpc_sym::TYPEDEF);
	  *s->stypedef = yyvsp[0].decl;
	  s->stypedef->type = strbuf ("struct ") << yyvsp[0].decl.type;
	  s->stypedef->id = getnewid (s->stypedef->id);
	}
    break;

  case 13:
#line 95 "./parse.yy"
    {
	  rpc_sym *s = &symlist.push_back ();
	  s->settype (rpc_sym::CONST);
	  s->sconst->id = yyvsp[-3].str;
	  s->sconst->val = yyvsp[-1].str;
	}
    break;

  case 14:
#line 104 "./parse.yy"
    {
	  rpc_sym *s = &symlist.push_back ();
	  s->settype (rpc_sym::ENUM);
	  s->senum->id = yyvsp[-1].str;
	}
    break;

  case 17:
#line 113 "./parse.yy"
    { yywarn ("comma not allowed at end of enum"); }
    break;

  case 18:
#line 117 "./parse.yy"
    {
	  rpc_sym *s = &symlist.push_back ();
	  s->settype (rpc_sym::STRUCT);
	  s->sstruct->id = yyvsp[-1].str;
	}
    break;

  case 20:
#line 126 "./parse.yy"
    {
	  rpc_sym *s = &symlist.push_back ();
	  s->settype (rpc_sym::UNION);
	  s->sunion->id = yyvsp[-6].str;
	  s->sunion->tagtype = yyvsp[-3].str;
	  s->sunion->tagid = yyvsp[-2].str;
	}
    break;

  case 22:
#line 137 "./parse.yy"
    {
	  rpc_sym *s = &symlist.push_back ();
	  s->settype (rpc_sym::PROGRAM);
	  s->sprogram->id = yyvsp[-1].str;
	}
    break;

  case 23:
#line 143 "./parse.yy"
    {
	  rpc_sym *s = &symlist.back ();
	  s->sprogram->val = yyvsp[-1].num;
	  qsort (s->sprogram->vers.base (), s->sprogram->vers.size (),
		 sizeof (rpc_vers), vers_compare);
	}
    break;

  case 26:
#line 155 "./parse.yy"
    {
	  rpc_sym *s = &symlist.back ();
	  rpc_vers *rv = &s->sprogram->vers.push_back ();
	  rv->id = yyvsp[-1].str;
	}
    break;

  case 27:
#line 161 "./parse.yy"
    {
	  rpc_sym *s = &symlist.back ();
	  rpc_vers *rv = &s->sprogram->vers.back ();
	  rv->val = yyvsp[-1].num;
	  qsort (rv->procs.base (), rv->procs.size (),
		 sizeof (rpc_proc), proc_compare);
	}
    break;

  case 30:
#line 174 "./parse.yy"
    {
	  rpc_sym *s = &symlist.back ();
	  rpc_vers *rv = &s->sprogram->vers.back ();
	  rpc_proc *rp = &rv->procs.push_back ();
	  rp->id = yyvsp[-6].str;
	  rp->val = yyvsp[-1].num;
	  rp->arg = yyvsp[-4].str;
	  rp->res = yyvsp[-7].str;
	}
    break;

  case 36:
#line 195 "./parse.yy"
    {
	  rpc_sym *s = &symlist.back ();
	  rpc_utag *ut = &s->sunion->cases.push_back ();
	  ut->tagvalid = false;
	  ut->swval = yyvsp[-1].str;
	}
    break;

  case 37:
#line 202 "./parse.yy"
    {
	  rpc_sym *s = &symlist.back ();
	  rpc_utag *ut = &s->sunion->cases.push_back ();
	  ut->tagvalid = false;
	}
    break;

  case 38:
#line 210 "./parse.yy"
    {
	  rpc_sym *s = &symlist.back ();
	  rpc_utag *ut = &s->sunion->cases.back ();
	  ut->tagvalid = true;
	  ut->tag = yyvsp[0].decl;
	}
    break;

  case 39:
#line 217 "./parse.yy"
    {
	  rpc_sym *s = &symlist.back ();
	  rpc_utag *ut = &s->sunion->cases.back ();
	  ut->tagvalid = true;
	  ut->tag.type = "void";
	  ut->tag.qual = rpc_decl::SCALAR;
	}
    break;

  case 42:
#line 230 "./parse.yy"
    { symlist.back ().sstruct->decls.push_back (yyvsp[0].decl); }
    break;

  case 43:
#line 233 "./parse.yy"
    {}
    break;

  case 44:
#line 234 "./parse.yy"
    {}
    break;

  case 45:
#line 238 "./parse.yy"
    { symlist.back ().senum->tags.push_back (yyvsp[0].cnst); }
    break;

  case 46:
#line 241 "./parse.yy"
    { yyval.cnst.id = yyvsp[-2].str; yyval.cnst.val = yyvsp[0].str; }
    break;

  case 47:
#line 242 "./parse.yy"
    { yyval.cnst.id = yyvsp[0].str; }
    break;

  case 48:
#line 246 "./parse.yy"
    { yyval.decl.id = yyvsp[-1].str; yyval.decl.type = yyvsp[-2].str; yyval.decl.qual = rpc_decl::SCALAR; }
    break;

  case 49:
#line 248 "./parse.yy"
    { yyval.decl.id = yyvsp[-1].str; yyval.decl.type = yyvsp[-2].str; yyval.decl.qual = rpc_decl::VEC;
	   yyval.decl.bound = "RPC_INFINITY";
	   yywarn ("strings require variable-length array declarations");
	 }
    break;

  case 50:
#line 253 "./parse.yy"
    { yyval.decl.id = yyvsp[-1].str; yyval.decl.type = yyvsp[-3].str; yyval.decl.qual = rpc_decl::PTR; }
    break;

  case 51:
#line 255 "./parse.yy"
    { yyval.decl.id = yyvsp[-4].str; yyval.decl.type = yyvsp[-5].str; yyval.decl.qual = rpc_decl::ARRAY;
	   yyval.decl.bound = yyvsp[-2].str; }
    break;

  case 52:
#line 258 "./parse.yy"
    { yyval.decl.id = yyvsp[-4].str; yyval.decl.type = yyvsp[-5].str; yyval.decl.qual = rpc_decl::ARRAY;
	   yyval.decl.bound = yyvsp[-2].str; }
    break;

  case 53:
#line 261 "./parse.yy"
    { yyval.decl.id = yyvsp[-4].str; yyval.decl.type = yyvsp[-5].str; yyval.decl.qual = rpc_decl::VEC; yyval.decl.bound = yyvsp[-2].str; }
    break;

  case 54:
#line 263 "./parse.yy"
    { yyval.decl.id = yyvsp[-4].str; yyval.decl.type = yyvsp[-5].str; yyval.decl.qual = rpc_decl::VEC; yyval.decl.bound = yyvsp[-2].str; }
    break;

  case 55:
#line 265 "./parse.yy"
    { yyval.decl.id = yyvsp[-4].str; yyval.decl.type = yyvsp[-5].str; yyval.decl.qual = rpc_decl::VEC; yyval.decl.bound = yyvsp[-2].str; }
    break;

  case 56:
#line 267 "./parse.yy"
    { yyval.decl.id = yyvsp[-3].str; yyval.decl.type = yyvsp[-4].str; yyval.decl.qual = rpc_decl::VEC;
	   yyval.decl.bound = "RPC_INFINITY"; }
    break;

  case 57:
#line 270 "./parse.yy"
    { yyval.decl.id = yyvsp[-3].str; yyval.decl.type = yyvsp[-4].str; yyval.decl.qual = rpc_decl::VEC;
	   yyval.decl.bound = "RPC_INFINITY"; }
    break;

  case 58:
#line 273 "./parse.yy"
    { yyval.decl.id = yyvsp[-3].str; yyval.decl.type = yyvsp[-4].str; yyval.decl.qual = rpc_decl::VEC;
	   yyval.decl.bound = "RPC_INFINITY"; }
    break;

  case 60:
#line 277 "./parse.yy"
    { yyval.str = "void"; }
    break;

  case 63:
#line 283 "./parse.yy"
    { yyval.str = "u_int32_t"; }
    break;

  case 64:
#line 284 "./parse.yy"
    { yyval.str = "int32_t"; }
    break;

  case 65:
#line 285 "./parse.yy"
    { yyval.str = "u_int32_t"; }
    break;

  case 66:
#line 286 "./parse.yy"
    { yyval.str = "int64_t"; }
    break;

  case 67:
#line 287 "./parse.yy"
    { yyval.str = "u_int64_t"; }
    break;

  case 68:
#line 288 "./parse.yy"
    { yyval.str = "double"; }
    break;

  case 69:
#line 289 "./parse.yy"
    { yyval.str = "quadruple"; }
    break;

  case 72:
#line 295 "./parse.yy"
    { yyval.num = strtoul (yyvsp[0].str, NULL, 0); }
    break;

  case 73:
#line 298 "./parse.yy"
    { yyval.str = getnewid (yyvsp[0].str); }
    break;

  case 74:
#line 301 "./parse.yy"
    { yyval.str = getid (yyvsp[0].str); }
    break;


    }

/* Line 999 of yacc.c.  */
#line 1477 "y.tab.c"

  yyvsp -= yylen;
  yyssp -= yylen;


  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;


  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if YYERROR_VERBOSE
      yyn = yypact[yystate];

      if (YYPACT_NINF < yyn && yyn < YYLAST)
	{
	  YYSIZE_T yysize = 0;
	  int yytype = YYTRANSLATE (yychar);
	  char *yymsg;
	  int yyx, yycount;

	  yycount = 0;
	  /* Start YYX at -YYN if negative to avoid negative indexes in
	     YYCHECK.  */
	  for (yyx = yyn < 0 ? -yyn : 0;
	       yyx < (int) (sizeof (yytname) / sizeof (char *)); yyx++)
	    if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
	      yysize += yystrlen (yytname[yyx]) + 15, yycount++;
	  yysize += yystrlen ("syntax error, unexpected ") + 1;
	  yysize += yystrlen (yytname[yytype]);
	  yymsg = (char *) YYSTACK_ALLOC (yysize);
	  if (yymsg != 0)
	    {
	      char *yyp = yystpcpy (yymsg, "syntax error, unexpected ");
	      yyp = yystpcpy (yyp, yytname[yytype]);

	      if (yycount < 5)
		{
		  yycount = 0;
		  for (yyx = yyn < 0 ? -yyn : 0;
		       yyx < (int) (sizeof (yytname) / sizeof (char *));
		       yyx++)
		    if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
		      {
			const char *yyq = ! yycount ? ", expecting " : " or ";
			yyp = yystpcpy (yyp, yyq);
			yyp = yystpcpy (yyp, yytname[yyx]);
			yycount++;
		      }
		}
	      yyerror (yymsg);
	      YYSTACK_FREE (yymsg);
	    }
	  else
	    yyerror ("syntax error; also virtual memory exhausted");
	}
      else
#endif /* YYERROR_VERBOSE */
	yyerror ("syntax error");
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
	 error, discard it.  */

      /* Return failure if at end of input.  */
      if (yychar == YYEOF)
        {
	  /* Pop the error token.  */
          YYPOPSTACK;
	  /* Pop the rest of the stack.  */
	  while (yyss < yyssp)
	    {
	      YYDSYMPRINTF ("Error: popping", yystos[*yyssp], yyvsp, yylsp);
	      yydestruct (yystos[*yyssp], yyvsp);
	      YYPOPSTACK;
	    }
	  YYABORT;
        }

      YYDSYMPRINTF ("Error: discarding", yytoken, &yylval, &yylloc);
      yydestruct (yytoken, &yylval);
      yychar = YYEMPTY;

    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*----------------------------------------------------.
| yyerrlab1 -- error raised explicitly by an action.  |
`----------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;	/* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (yyn != YYPACT_NINF)
	{
	  yyn += YYTERROR;
	  if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
	    {
	      yyn = yytable[yyn];
	      if (0 < yyn)
		break;
	    }
	}

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
	YYABORT;

      YYDSYMPRINTF ("Error: popping", yystos[*yyssp], yyvsp, yylsp);
      yydestruct (yystos[yystate], yyvsp);
      yyvsp--;
      yystate = *--yyssp;

      YY_STACK_PRINT (yyss, yyssp);
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  YYDPRINTF ((stderr, "Shifting error token, "));

  *++yyvsp = yylval;


  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#ifndef yyoverflow
/*----------------------------------------------.
| yyoverflowlab -- parser overflow comes here.  |
`----------------------------------------------*/
yyoverflowlab:
  yyerror ("parser stack overflow");
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
  return yyresult;
}


#line 304 "./parse.yy"

symlist_t symlist;

static int
proc_compare (const void *_a, const void *_b)
{
  rpc_proc *a = (rpc_proc *) _a;
  rpc_proc *b = (rpc_proc *) _b;
  return a->val < b->val ? -1 : a->val != b->val;
}

static int
vers_compare (const void *_a, const void *_b)
{
  rpc_vers *a = (rpc_vers *) _a;
  rpc_vers *b = (rpc_vers *) _b;
  return a->val < b->val ? -1 : a->val != b->val;
}

void
checkliterals ()
{
  for (size_t i = 0; i < litq.size (); i++) {
    rpc_sym *s = &symlist.push_back ();
    s->settype (rpc_sym::LITERAL);
    *s->sliteral = litq[i];
  }
  litq.clear ();
}

static str
getnewid (str id)
{
  if (ids[id])
    yywarn ("redefinition of symbol " << id);
  else
    ids.insert (id);
  if (idprefix)
    id = idprefix << id;
  return id;
}

static str
getid (str id)
{
  if (idprefix && ids[id])
    id = idprefix << id;
  return id;
}

