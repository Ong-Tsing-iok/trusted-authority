import * as mcl from "mcl-wasm";
import { logger } from "./Logger.js";
import {
  insertParams,
  getParams,
  insertArrayParams,
  getArrayParams,
  getAttributeArrayParams,
} from "./Database.js";

export class TrustedAuthority {
  msk;
  _pp;
  constructor() {
    if (!this.retrieveParams()) {
      this.SetUp();
      this.storeParams();
    }
  }

  get pp() {
    this.updateGlobalAttribute();
    return this._pp;
  }

  retrieveParams() {
    const params = getParams.get();
    if (!params) return false;
    const arrayParams = getArrayParams.all();
    const U = new Array(arrayParams.length - 1);
    const s = new Array(arrayParams.length);
    const h_i = new Array(arrayParams.length);
    arrayParams.forEach((array_param) => {
      s[array_param.id] = mcl.deserializeHexStrToFr(array_param.s);
      h_i[array_param.id] = mcl.deserializeHexStrToG1(array_param.h_i);
      if (array_param.u != "EOF") U[array_param.id] = array_param.u;
    });
    this.msk = {
      alpha: mcl.deserializeHexStrToFr(params.alpha),
      beta: mcl.deserializeHexStrToFr(params.beta),
      s,
    };
    this._pp = {
      g1: mcl.deserializeHexStrToG1(params.g1),
      g2: mcl.deserializeHexStrToG2(params.g2),
      eggalpha: mcl.deserializeHexStrToGT(params.eggalpha),
      h: mcl.deserializeHexStrToG1(params.h),
      h_i,
      U,
    };
    return true;
  }
  storeParams() {
    insertParams.run(
      this.msk.alpha.serializeToHexStr(),
      this.msk.beta.serializeToHexStr(),
      this._pp.g1.serializeToHexStr(),
      this._pp.g2.serializeToHexStr(),
      this._pp.eggalpha.serializeToHexStr(),
      this._pp.h.serializeToHexStr()
    );
    let i;
    for (i = 0; i < this._pp.U.length; i++) {
      insertArrayParams.run(
        i,
        this._pp.U[i],
        this.msk.s[i].serializeToHexStr(),
        this._pp.h_i[i].serializeToHexStr()
      );
    }
    insertArrayParams.run(
      i,
      "EOF",
      this.msk.s[i].serializeToHexStr(),
      this._pp.h_i[i].serializeToHexStr()
    );
    logger.info(`Parameters stored in database.`);
  }

  updateGlobalAttribute() {
    // Update global attribute from database (as CLI could modify it)
    const attrParams = getAttributeArrayParams.all();
    attrParams.forEach((param) => {
      this._pp.U[param.id] = param.u;
    });
  }

  SetUp() {
    logger.info(`This is the first time for the server to run. Doing setup.`);
    const attr_num = process.env.ATTR_NUM || 32;
    const U = ["機密", "極機密", "絕對機密"].concat(
      ...Array(Math.max(attr_num - 3, 0)).fill("None")
    );
    // console.log(U.length);
    // Follow convention from https://github.com/zcash/librustzcash/blob/6e0364cd42a2b3d2b958a54771ef51a8db79dd29/pairing/src/bls12_381/README.md#generators
    const g1 = new mcl.G1();
    g1.setStr(
      "1 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569"
    );

    const g2 = new mcl.G2();
    g2.setStr(
      "1 352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160 3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758 1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905 927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582"
    );
    // console.log(P)
    // console.log(Q)
    const alpha = new mcl.Fr();
    const beta = new mcl.Fr();
    alpha.setByCSPRNG();
    beta.setByCSPRNG();
    const s = new Array(U.length + 1);
    const h_i = new Array(s.length);
    for (let i = 0; i < s.length; i++) {
      const si = new mcl.Fr();
      si.setByCSPRNG();
      s[i] = si;
      const hi = mcl.mul(g1, si);
      h_i[i] = hi;
    }
    const h = mcl.mul(g1, beta);
    const eggalpha = mcl.pow(mcl.pairing(g1, g2), alpha);
    const msk = { alpha, beta, s };
    const pp = { g1, g2, eggalpha, h, h_i, U };
    this.msk = msk;
    this._pp = pp;
  }

  KeyGen(R) {
    this.updateGlobalAttribute();
    // Attribute vector y
    const y = new Array(this.msk.s.length);
    let i;
    for (i = 0; i < this._pp.U.length; i++) {
      y[i] = R.includes(this._pp.U[i]) ? 1 : 0;
    }
    y[i] = 1;
    // console.log(y);
    const theta = new mcl.Fr();
    const mu = new mcl.Fr();
    theta.setByCSPRNG();
    mu.setByCSPRNG();
    const sk1 = mcl.mul(
      this._pp.g2,
      mcl.div(mcl.add(this.msk.alpha, mu), this.msk.beta)
    );
    const sk2 = mcl.mul(this._pp.g2, mcl.inv(this.msk.beta));
    const sk3 = mcl.mul(this._pp.g2, theta);
    let innerProd = new mcl.Fr(); // will be zero
    // assert.equal(this.msk.s.length, y.length);
    for (i = 0; i < this.msk.s.length; i++) {
      if (y[i] == 1) {
        innerProd = mcl.add(innerProd, this.msk.s[i]);
      }
    }
    const sky = mcl.mul(
      this._pp.g2,
      mcl.div(mcl.sub(mu, mcl.mul(theta, innerProd)), this.msk.beta)
    );
    const SK = { sk1, sk2, sk3, sky };
    // console.log(SK);
    // console.log(y);
    return { SK, y };
  }
}
