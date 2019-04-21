/*************************************************************************************************
 * The test cases of the cache hash database for RCX
 *                                                               Copyright (C) 2009-2012 FAL Labs
 * This file is part of Kyoto Cabinet.
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or any later version.
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 *************************************************************************************************/


#include <kccachedb.h>
#include <stdlib.h>
#include <unistd.h>
#include "cmdcommon.h"

#include <numa.h>
#include <urcu.h>

/* NOTE: dependent to underlying CPU topology! */
int cpu_pin_map[] = {
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,
    72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,
    18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,
    90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,
    36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,
    108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,
    54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,
    126,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143};

#define CPU_PER_NODES (36)

// global variables
const char* g_progname;                  // program name
uint32_t g_randseed;                     // random seed
int64_t g_memusage;                      // memory usage
uint32_t g_readrate;                     // read rate (percent)
bool g_stop_work;


// function prototypes
int main(int argc, char** argv);
static void usage();
static void dberrprint(kc::BasicDB* db, int32_t line, const char* func);
static void dbmetaprint(kc::BasicDB* db, bool verbose);
static int32_t runorder(int argc, char** argv);
static int32_t procorder(int64_t rnum, int32_t thnum, bool rnd, bool etc, bool tran,
                         int32_t opts, int64_t bnum, int64_t capcnt, int64_t capsiz, bool lv);

// main routine
int main(int argc, char** argv) {
  rcu_init();
  g_progname = argv[0];
  const char* ebuf = kc::getenv("KCRNDSEED");
  g_randseed = ebuf ? (uint32_t)kc::atoi(ebuf) : (uint32_t)(kc::time() * 1000);
  mysrand(g_randseed);
  g_memusage = memusage();
  g_readrate = 90;
  g_stop_work = false;
  kc::setstdiobin();
  if (argc < 2) usage();
  int32_t rv = 0;
  if (!std::strcmp(argv[1], "order")) {
    rv = runorder(argc, argv);
  } else {
    usage();
  }
  if (rv != 0) {
    oprintf("FAILED: KCRNDSEED=%u PID=%ld", g_randseed, (long)kc::getpid());
    for (int32_t i = 0; i < argc; i++) {
      oprintf(" %s", argv[i]);
    }
    oprintf("\n\n");
  }
  return rv;
}


// print the usage and exit
static void usage() {
  eprintf("%s: test cases of the cache hash database of Kyoto Cabinet\n", g_progname);
  eprintf("\n");
  eprintf("usage:\n");
  eprintf("  %s order [-th num] [-rd rate] [-rnd] [-etc] [-tran] [-tc]"
          " [-bnum num] [-capcnt num] [-capsiz num] [-lv] rnum\n", g_progname);
  eprintf("\n");
  std::exit(1);
}


// print the error message of a database
static void dberrprint(kc::BasicDB* db, int32_t line, const char* func) {
  const kc::BasicDB::Error& err = db->error();
  oprintf("%s: %d: %s: %s: %d: %s: %s\n",
          g_progname, line, func, db->path().c_str(), err.code(), err.name(), err.message());
}


// print members of a database
static void dbmetaprint(kc::BasicDB* db, bool verbose) {
  if (verbose) {
    std::map<std::string, std::string> status;
    status["opaque"] = "";
    status["bnum_used"] = "";
    if (db->status(&status)) {
      uint32_t type = kc::atoi(status["type"].c_str());
      oprintf("type: %s (%s) (type=0x%02X)\n",
              kc::BasicDB::typecname(type), kc::BasicDB::typestring(type), type);
      uint32_t rtype = kc::atoi(status["realtype"].c_str());
      if (rtype > 0 && rtype != type)
        oprintf("real type: %s (%s) (realtype=0x%02X)\n",
                kc::BasicDB::typecname(rtype), kc::BasicDB::typestring(rtype), rtype);
      uint32_t chksum = kc::atoi(status["chksum"].c_str());
      oprintf("format version: %s (libver=%s.%s) (chksum=0x%02X)\n", status["fmtver"].c_str(),
              status["libver"].c_str(), status["librev"].c_str(), chksum);
      oprintf("path: %s\n", status["path"].c_str());
      int32_t flags = kc::atoi(status["flags"].c_str());
      oprintf("status flags:");
      if (flags & kc::CacheDB::FOPEN) oprintf(" open");
      if (flags & kc::CacheDB::FFATAL) oprintf(" fatal");
      oprintf(" (flags=%d)", flags);
      if (kc::atoi(status["recovered"].c_str()) > 0) oprintf(" (recovered)");
      if (kc::atoi(status["reorganized"].c_str()) > 0) oprintf(" (reorganized)");
      oprintf("\n", flags);
      int32_t opts = kc::atoi(status["opts"].c_str());
      oprintf("options:");
      if (opts & kc::CacheDB::TSMALL) oprintf(" small");
      if (opts & kc::CacheDB::TLINEAR) oprintf(" linear");
      if (opts & kc::CacheDB::TCOMPRESS) oprintf(" compress");
      oprintf(" (opts=%d)\n", opts);
      if (status["opaque"].size() >= 16) {
        const char* opaque = status["opaque"].c_str();
        oprintf("opaque:");
        if (std::count(opaque, opaque + 16, 0) != 16) {
          for (int32_t i = 0; i < 16; i++) {
            oprintf(" %02X", ((unsigned char*)opaque)[i]);
          }
        } else {
          oprintf(" 0");
        }
        oprintf("\n");
      }
      int64_t bnum = kc::atoi(status["bnum"].c_str());
      int64_t bnumused = kc::atoi(status["bnum_used"].c_str());
      int64_t count = kc::atoi(status["count"].c_str());
      double load = 0;
      if (count > 0 && bnumused > 0) {
        load = (double)count / bnumused;
        if (!(opts & kc::CacheDB::TLINEAR)) load = std::log(load + 1) / std::log(2.0);
      }
      oprintf("buckets: %lld (used=%lld) (load=%.2f)\n",
              (long long)bnum, (long long)bnumused, load);
      std::string cntstr = unitnumstr(count);
      int64_t capcnt = kc::atoi(status["capcnt"].c_str());
      oprintf("count: %lld (%s) (capcnt=%lld)\n", count, cntstr.c_str(), (long long)capcnt);
      int64_t size = kc::atoi(status["size"].c_str());
      std::string sizestr = unitnumstrbyte(size);
      int64_t capsiz = kc::atoi(status["capsiz"].c_str());
      oprintf("size: %lld (%s) (capsiz=%lld)\n", size, sizestr.c_str(), (long long)capsiz);
    }
  } else {
    oprintf("count: %lld\n", (long long)db->count());
    oprintf("size: %lld\n", (long long)db->size());
  }
  int64_t musage = memusage();
  if (musage > 0) oprintf("memory: %lld\n", (long long)(musage - g_memusage));
}


// parse arguments of order command
static int32_t runorder(int argc, char** argv) {
  bool argbrk = false;
  const char* rstr = NULL;
  int32_t thnum = 1;
  bool rnd = false;
  bool etc = false;
  bool tran = false;
  int32_t opts = 0;
  int64_t bnum = -1;
  int64_t capcnt = -1;
  int64_t capsiz = -1;
  bool lv = false;
  for (int32_t i = 2; i < argc; i++) {
    if (!argbrk && argv[i][0] == '-') {
      if (!std::strcmp(argv[i], "--")) {
        argbrk = true;
      } else if (!std::strcmp(argv[i], "-th")) {
        if (++i >= argc) usage();
        thnum = kc::atoix(argv[i]);
      } else if (!std::strcmp(argv[i], "-rd")) {
        if (++i >= argc) usage();
        g_readrate = kc::atoix(argv[i]);
      } else if (!std::strcmp(argv[i], "-rnd")) {
        rnd = true;
      } else if (!std::strcmp(argv[i], "-etc")) {
        etc = true;
      } else if (!std::strcmp(argv[i], "-tran")) {
        tran = true;
      } else if (!std::strcmp(argv[i], "-tc")) {
        opts |= kc::CacheDB::TCOMPRESS;
      } else if (!std::strcmp(argv[i], "-bnum")) {
        if (++i >= argc) usage();
        bnum = kc::atoix(argv[i]);
      } else if (!std::strcmp(argv[i], "-capcnt")) {
        if (++i >= argc) usage();
        capcnt = kc::atoix(argv[i]);
      } else if (!std::strcmp(argv[i], "-capsiz")) {
        if (++i >= argc) usage();
        capsiz = kc::atoix(argv[i]);
      } else if (!std::strcmp(argv[i], "-lv")) {
        lv = true;
      } else {
        usage();
      }
    } else if (!rstr) {
      argbrk = true;
      rstr = argv[i];
    } else {
      usage();
    }
  }
  if (!rstr) usage();
  int64_t rnum = kc::atoix(rstr);
  if (rnum < 1 || thnum < 1) usage();
  if (thnum > THREADMAX) thnum = THREADMAX;
  int32_t rv = procorder(rnum, thnum, rnd, etc, tran, opts, bnum, capcnt, capsiz, lv);
  return rv;
}

#define rcxt_gen_key(buf, n) std::sprintf(buf, "%08lld", (long long)n);

static inline
bool rcxt_set_rec(kc::BasicDB* db, char* kb, size_t ks, char* vb, size_t vs) {
  bool err = false;

  if (!db->set(kb, ks, vb, vs)) {
    dberrprint(db, __LINE__, "DB::set");
    err = true;
  }

  return err;
}

static inline
bool rcxt_add_rec(kc::BasicDB* db, char* kb, size_t ks, char* vb, size_t vs) {
  bool err = false;

  if (!db->add(kb, ks, kb, ks) &&
      db->error() != kc::BasicDB::Error::DUPREC) {
    dberrprint(db, __LINE__, "DB::add");
    err = true;
  }

  return err;
}

static inline bool rcxt_rm_rec(kc::BasicDB* db, char *kb, size_t ks) {
  bool err = false;

  if (!db->remove(kb, ks) &&
      db->error() != kc::BasicDB::Error::NOREC) {
    dberrprint(db, __LINE__, "DB::remove");
    err = true;
  }

  return err;
}

bool rcxt_get_rec(kc::BasicDB* db, char *kb, size_t ks) {
  size_t vsiz;
  char* vbuf;
  bool err = false;

  vbuf = db->get(kb, ks, &vsiz);
  if (vbuf) {
    if (vsiz < ks || std::memcmp(vbuf, kb, ks)) {
      dberrprint(db, __LINE__, "DB::get");
      err = true;
    }
    delete[] vbuf;
  }
  return err;
}

struct work_perf {
  uint64_t nr_gets;
  uint64_t nr_sets;
  uint64_t nr_rms;
};

static inline uint32_t randrange(struct drand48_data* drand_buffer,
																int32_t range) {
  long int drand_res;
  lrand48_r(drand_buffer, &drand_res);
  return drand_res % range;
}

extern __thread int32_t numa_node_id;

#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))

// perform order command
static int32_t procorder(int64_t rnum, int32_t thnum, bool rnd, bool etc, bool tran,
                         int32_t opts, int64_t bnum, int64_t capcnt, int64_t capsiz, bool lv) {
  oprintf("<In-order Test>\n  seed=%u  rnum=%lld  thnum=%d  rdrate=%u  rnd=%d  etc=%d  tran=%d"
          "  opts=%d  bnum=%lld  capcnt=%lld  capsiz=%lld  lv=%d\n\n",
          g_randseed, (long long)rnum, thnum, g_readrate, rnd, etc, tran,
          opts, (long long)bnum, (long long)capcnt, (long long)capsiz, lv);
  bool err = false;
  kc::CacheDB db;
  oprintf("opening the database:\n");
  double stime = kc::time();
  db.tune_logger(stdlogger(g_progname, &std::cout),
                 lv ? kc::UINT32MAX : kc::BasicDB::Logger::WARN | kc::BasicDB::Logger::ERROR);
  if (opts > 0) db.tune_options(opts);
  if (bnum > 0) db.tune_buckets(bnum);
  if (capcnt > 0) db.cap_count(capcnt);
  if (capsiz > 0) db.cap_size(capsiz);
  /* Turn off LRU rotation to let get() operation to be read only. */
  db.switch_rotation(false);
  if (!db.open("*", kc::CacheDB::OWRITER | kc::CacheDB::OCREATE | kc::CacheDB::OTRUNCATE)) {
    dberrprint(&db, __LINE__, "DB::open");
    err = true;
  }
  double etime = kc::time();
  dbmetaprint(&db, false);
  oprintf("time: %.3f\n", etime - stime);

  oprintf("fill db with %lld records\n", rnum / 2);
  stime = kc::time();

  char kbuf[RECBUFSIZ];
  size_t ksiz;
  struct bitmask *cpumask;

  cpumask = numa_allocate_cpumask();
  numa_bitmask_setbit(cpumask, 143);
  numa_sched_setaffinity(0, cpumask);
  numa_free_cpumask(cpumask);

  numa_node_id = 143 / CPU_PER_NODES;

  for (int64_t i = 0; i < rnum / 2; i++) {
    ksiz = rcxt_gen_key(kbuf, i);
    rcxt_set_rec(&db, kbuf, ksiz, kbuf, ksiz);
  }
  etime = kc::time();
  dbmetaprint(&db, false);
  oprintf("time: %.3f\n", etime - stime);

  oprintf("do work:\n");
  stime = kc::time();
  class ThreadWork : public kc::Thread {
   public:
    void setparams(int32_t id, kc::BasicDB* db, int64_t rnum,
         struct work_perf* perf) {
      id_ = id;
      db_ = db;
      rnum_ = rnum;
      err_ = false;
      perf_ = perf;
    }
    bool error() {
      return err_;
    }
    void run() {
      char kb[RECBUFSIZ];
      size_t ks;
      struct drand48_data drand_buffer;
      struct bitmask *cpumask;

      rcu_register_thread();
      srand48_r(id_ * 42, &drand_buffer);
      cpumask = numa_allocate_cpumask();
      numa_bitmask_setbit(cpumask, cpu_pin_map[id_]);
      numa_sched_setaffinity(0, cpumask);
      numa_free_cpumask(cpumask);

      numa_node_id = id_ / CPU_PER_NODES;

      while(!ACCESS_ONCE(g_stop_work)) {
          ks = rcxt_gen_key(kb, randrange(&drand_buffer, rnum_));
        if (randrange(&drand_buffer, 100) < g_readrate) {
          /* read */
          rcxt_get_rec(db_, kb, ks);
          perf_->nr_gets++;
        } else {
          /* update */
          if (randrange(&drand_buffer, 2) < 1) {
            /* set */
            rcxt_set_rec(db_, kb, ks, kb, ks);
            perf_->nr_sets++;
          } else {
            /* remove */
            rcxt_rm_rec(db_, kb, ks);
            perf_->nr_rms++;
          }
        }
      }
      rcu_unregister_thread();
    }

   private:
    int32_t id_;
    kc::BasicDB* db_;
    int64_t rnum_;
    bool err_;
    struct work_perf *perf_;
  };

  struct work_perf work_perfs[THREADMAX] = {0,};
  ThreadWork threadworks[THREADMAX];
  for (int32_t i = 0; i < thnum; i++) {
    threadworks[i].setparams(i, &db, rnum, &work_perfs[i]);
    threadworks[i].start();
  }
  sleep(3);
  ACCESS_ONCE(g_stop_work) = true;
  for (int32_t i = 0; i < thnum; i++) {
    threadworks[i].join();
    if (threadworks[i].error()) err = true;
  }

  etime = kc::time();
  dbmetaprint(&db, false);
  oprintf("time: %.3f\n", etime - stime);

  uint64_t total_nr_gets = 0;
  uint64_t total_nr_sets = 0;
  uint64_t total_nr_rms = 0;
  for (int32_t i = 0; i < thnum; i++) {
    total_nr_gets += work_perfs[i].nr_gets;
    total_nr_sets += work_perfs[i].nr_sets;
    total_nr_rms += work_perfs[i].nr_rms;
  }
  oprintf("nr_gets: %llu\n", total_nr_gets);
  oprintf("nr_sets: %llu\n", total_nr_sets);
  oprintf("nr_rms: %llu\n", total_nr_rms);
  oprintf("nr_ops: %llu\n", total_nr_gets + total_nr_sets + total_nr_rms);

  exit(1);

  oprintf("closing the database:\n");
  stime = kc::time();
  if (!db.close()) {
    dberrprint(&db, __LINE__, "DB::close");
    err = true;
  }
  etime = kc::time();
  oprintf("time: %.3f\n", etime - stime);
  oprintf("%s\n\n", err ? "error" : "ok");

  return err ? 1 : 0;
}

// END OF FILE
