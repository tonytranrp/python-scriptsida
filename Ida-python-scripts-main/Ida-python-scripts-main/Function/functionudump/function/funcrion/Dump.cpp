#include <cmath>
#include <algorithm>
#include <cstdint>
#include <array>
#include <limits>
#include <bit>
#include <glm/glm.hpp>
#include <vector>
#include <map>

namespace mce {
    struct Radian {
        float value;
        explicit Radian(float v) : value(v) {}
    };

    struct Degree {
        float value;
        explicit Degree(float v) : value(v) {}
    };
}
namespace AABB {

float AABB(Vec3 a1, float a2)
  {
  glm::vec4 v3;
  glm::vec4 v4;
  float v5;
  AABB * result;
  v3 = *(glm::vec4 *)&a3;
  v3.m128_f32[{0}] = *(float *)&a3 + *(float *)a2;
  v4 = *(glm::vec4 *)&a3;
  v4.m128_f32[{0}] = *(float *)&a3 + *((float *)a2 + 1);
  v5 = *(float *)&a3 + *((float *)a2 + 2);
  *(uint64_t *)this = *(uint64_t *)a2;
  *((uint32_t *)this + 2) = *((uint32_t *)a2 + 2);
  result = this;
  *(uint64_t *)((char *)this + 12) = _mm_unpacklo_ps(v3, v4).m128_u64[{0}];
  *((float *)this + 5) = v5;
  return result;
}

float AABB(float a1, float a2, float a3, float a4, float a5, float a6)
  {
  AABB * result;
  result = this;
  *((float *)this + 3) = a5;
  *(float *)this = a2;
  *((float *)this + 5) = a7;
  *((float *)this + 1) = a3;
  *((float *)this + 2) = a4;
  *((float *)this + 4) = a6;
  return result;
}

float operator==(AABB a1)
  {
  return * a2 == * a1 && a2[{1}] == a1[{1}] && a2[{2}] == a1[{2}] && a2[{3}] == a1[{3}] && a2[{4}] == a1[{4}] && a2[{5}] == a1[{5}];
}

float operator!=(AABB a1)
  {
  return * a2 != * a1 || a2[{1}] != a1[{1}] || a2[{2}] != a1[{2}] || a2[{3}] != a1[{3}] || a2[{4}] != a1[{4}] || a2[{5}] != a1[{5}];
}

float axisInside(AABB a1, Vec3 a2)
  {
  float v4;
  int64_t result;
  float v6;
  float v7;
  float v8;
  float v9;
  float v10;
  if ( * a4 > 0.0 )
    {
    v4 = a1[{3}] - * a3;
    result = a2;
    *(float *)a2 = v4;
    return result;
  }
  if ( * a4 < 0.0 )
    {
    v6 = * a1 - a3[{3}];
    result = a2;
    *(float *)a2 = v6;
    return result;
  }
  v7 = a4[{1}];
  if ( v7 > 0.0 )
    {
    v8 = a1[{4}] - a3[{1}];
    *(uint32_t *)a2 = 0;
    *(float *)(a2 + 4) = v8;
    LABEL_7:
    *(uint32_t *)(a2 + 8) = 0;
    return a2;
  }
  if ( v7 >= 0.0 )
    {
    v10 = a4[{2}];
    if ( v10 <= 0.0 )
      {
      if ( v10 >= 0.0 )
      goto LABEL_7;
      result = a2;
      *(float *)(a2 + 8) = a1[{2}] - a3[{5}];
    }
    else
      {
      result = a2;
      *(float *)(a2 + 8) = a1[{5}] - a3[{2}];
    }
  }
  else
    {
    v9 = a1[{1}] - a3[{4}];
    *(uint32_t *)a2 = 0;
    *(uint32_t *)(a2 + 8) = 0;
    result = a2;
    *(float *)(a2 + 4) = v9;
  }
  return result;
}

float clip(Vec3 a1, Vec3 a2)
  {
  float v4;
  float v6;
  float v8;
  float v9;
  float v10;
  float v11;
  glm::vec4 v12;
  float v13;
  float v14;
  float v15;
  float v16;
  char v17;
  float v18;
  float v19;
  char v20;
  float v21;
  float v22;
  float v23;
  float v24;
  char v25;
  char v26;
  float v27;
  float v28;
  char v29;
  char v30;
  float * v31;
  float v32;
  float v33;
  float v34;
  float v35;
  float v36;
  float v37;
  float v38;
  float v39;
  float v40;
  float v41;
  float * v42;
  unsigned int v43;
  int64_t result;
  char v45;
  char v46;
  char v47;
  char v48;
  int v49;
  int64_t v50;
  glm::vec4 v51;
  glm::vec4 v52;
  float v53;
  float v54;
  float v55;
  float v56;
  float v57;
  float v58;
  float v59;
  float v60;
  float v61;
  float v62;
  float v63;
  float v64;
  float v65;
  float v66;
  float v67;
  float v68;
  float v69;
  float v70;
  float v71;
  float v72;
  float v73;
  v4 = a1[{3}];
  v6 = * a1;
  v55 = v4;
  if ( * a1 >= v4 || a1[{4}] <= a1[{1}] || a1[{5}] <= a1[{2}] )
    {
    v51 = (glm::vec4)*(unsigned int *)a4;
    v51.m128_f32[{0}] = v51.m128_f32[{0}] - * a3;
    v52 = (glm::vec4)*((unsigned int *)a4 + 1);
    v52.m128_f32[{0}] = v52.m128_f32[{0}] - a3[{1}];
    v53 = a4[{2}] - a3[{2}];
    *(uint64_t *)a2 = *(uint64_t *)a3;
    *(float *)(a2 + 8) = a3[{2}];
    *(uint32_t *)(a2 + 24) = 3;
    *(uint8_t *)(a2 + 28) = 0;
    *(uint64_t *)(a2 + 12) = _mm_unpacklo_ps(v51, v52).m128_u64[{0}];
    *(float *)(a2 + 20) = v53;
    *(uint32_t *)(a2 + 40) = 0;
    *(uint64_t *)(a2 + 44) = *(uint64_t *)a4;
    *(float *)(a2 + 52) = a4[{2}];
    WeakStorageEntity::WeakStorageEntity((WeakStorageEntity *)(a2 + 56));
    goto LABEL_98;
  }
  v8 = * a3;
  v9 = 0.0;
  v10 = 0.0;
  v11 = 0.0;
  v12 = (glm::vec4)*(unsigned int *)a4;
  v12.m128_f32[{0}] = v12.m128_f32[{0}] - * a3;
  v13 = 0.0;
  v14 = 0.0;
  v56 = 0.0;
  v58 = 0.0;
  v59 = 0.0;
  v60 = 0.0;
  v61 = 0.0;
  v63 = 0.0;
  v64 = 0.0;
  v67 = 0.0;
  v70 = 0.0;
  v15 = 0.0;
  v71 = 0.0;
  v16 = 0.0;
  v72 = 0.0;
  v73 = 0.0;
  v57 = 0.0;
  v62 = 0.0;
  v65 = 0.0;
  v66 = 0.0;
  v68 = 0.0;
  v69 = 0.0;
  if ( (float)(v12.m128_f32[{0}] * v12.m128_f32[{0}]) >= 0.0000001 )
    {
    v18 = (float)(v6 - v8) / v12.m128_f32[{0}];
    if ( v18 < 0.0 || v18 > 1.0 )
      {
      v17 = 0;
    }
    else
      {
      v17 = 1;
      v11 = (float)((float)(a4[{1}] - a3[{1}]) * v18) + a3[{1}];
      v13 = (float)((float)(a4[{2}] - a3[{2}]) * v18) + a3[{2}];
      v71 = (float)(v18 * v12.m128_f32[{0}]) + v8;
      v72 = v11;
      v73 = v13;
    }
    v19 = (float)(v4 - v8) / v12.m128_f32[{0}];
    if ( v19 >= 0.0 && v19 <= 1.0 )
      {
      v20 = 1;
      v21 = (float)((float)(a4[{2}] - a3[{2}]) * v19) + a3[{2}];
      v56 = (float)(v19 * v12.m128_f32[{0}]) + v8;
      v22 = a4[{1}] - a3[{1}];
      v58 = v21;
      v9 = (float)(v22 * v19) + a3[{1}];
      v57 = v9;
      goto LABEL_15;
    }
    v9 = 0.0;
  }
  else
    {
    v17 = 0;
  }
  v20 = 0;
  LABEL_15:
  v23 = a3[{1}];
  v24 = a4[{1}] - v23;
  v54 = v24;
  if ( (float)(v24 * v24) < 0.0000001 )
    {
    v25 = 0;
    LABEL_17:
    v26 = 0;
    goto LABEL_18;
  }
  v33 = (float)(a1[{1}] - v23) / v24;
  if ( v33 < 0.0 || v33 > 1.0 )
    {
    v25 = 0;
    v36 = a4[{1}] - v23;
  }
  else
    {
    v25 = 1;
    v59 = (float)(v12.m128_f32[{0}] * v33) + v8;
    v34 = v33 * v24;
    v35 = (float)(a4[{2}] - a3[{2}]) * v33;
    v60 = v34 + v23;
    v36 = v54;
    v61 = v35 + a3[{2}];
  }
  v37 = (float)(a1[{4}] - v23) / v36;
  if ( v37 < 0.0 || v37 > 1.0 )
  goto LABEL_17;
  v26 = 1;
  v16 = (float)(v12.m128_f32[{0}] * v37) + v8;
  v63 = (float)(v37 * v36) + v23;
  v38 = a4[{2}] - a3[{2}];
  v62 = v16;
  v64 = (float)(v38 * v37) + a3[{2}];
  LABEL_18:
  v27 = a3[{2}];
  v28 = a4[{2}] - v27;
  if ( (float)(v28 * v28) >= 0.0000001 )
    {
    v39 = (float)(a1[{2}] - v27) / v28;
    if ( v39 < 0.0 || v39 > 1.0 )
      {
      v40 = v54;
      v29 = 0;
    }
    else
      {
      v40 = v54;
      v29 = 1;
      v15 = (float)(v39 * v54) + v23;
      v65 = (float)(v12.m128_f32[{0}] * v39) + v8;
      v66 = v15;
      v67 = (float)(v39 * v28) + v27;
    }
    v41 = (float)(a1[{5}] - v27) / v28;
    if ( v41 >= 0.0 && v41 <= 1.0 )
      {
      v30 = 1;
      v10 = (float)(v12.m128_f32[{0}] * v41) + v8;
      v14 = (float)(v41 * v40) + v23;
      v68 = v10;
      v70 = (float)(v41 * v28) + v27;
      v69 = v14;
      goto LABEL_21;
    }
  }
  else
    {
    v29 = 0;
  }
  v30 = 0;
  LABEL_21:
  v31 = a1 + 1;
  if ( !v17 || v11 < * v31 || v11 > a1[{4}] || v13 < a1[{2}] || v13 > a1[{5}] )
  v17 = 0;
  if ( !v20 || v9 < * v31 || v9 > a1[{4}] || v58 < a1[{2}] || v58 > a1[{5}] )
  v20 = 0;
  if ( !v25 || v59 < v6 )
    {
    v32 = v55;
    LABEL_54:
    v25 = 0;
    goto LABEL_55;
  }
  v32 = a1[{3}];
  if ( v59 > v32 || v61 < a1[{2}] || v61 > a1[{5}] )
  goto LABEL_54;
  LABEL_55:
  if ( !v26 || v16 < v6 || v16 > v32 || v64 < a1[{2}] || v64 > a1[{5}] )
  v26 = 0;
  if ( !v29 || v65 < v6 || v65 > v32 || v15 < * v31 || v15 > a1[{4}] )
  v29 = 0;
  if ( !v30 || v10 < v6 || v10 > v32 || v14 < * v31 || v14 > a1[{4}] )
  v30 = 0;
  v42 = &v71;
  if ( !v17 )
  if ( v20
  && (!v42
  || (float)((float)((float)((float)(v9 - v23) * (float)(v9 - v23)) + (float)((float)(v56 - v8) * (float)(v56 - v8)))
  + (float)((float)(v58 - v27) * (float)(v58 - v27))) < (float)((float)((float)((float)(v42[{1}] - v23)
  * (float)(v42[{1}] - v23))
  + (float)((float)(* v42 - v8)
  * (float)(* v42 - v8)))
  + (float)((float)(v42[{2}] - v27)
  * (float)(v42[{2}] - v27)))) )
    {
    v42 = &v56;
  }
  if ( v25
  && (!v42
  || (float)((float)((float)((float)(v60 - v23) * (float)(v60 - v23)) + (float)((float)(v59 - v8) * (float)(v59 - v8)))
  + (float)((float)(v61 - v27) * (float)(v61 - v27))) < (float)((float)((float)((float)(v42[{1}] - v23)
  * (float)(v42[{1}] - v23))
  + (float)((float)(* v42 - v8)
  * (float)(* v42 - v8)))
  + (float)((float)(v42[{2}] - v27)
  * (float)(v42[{2}] - v27)))) )
    {
    v42 = &v59;
  }
  if ( v26
  && (!v42
  || (float)((float)((float)((float)(v16 - v8) * (float)(v16 - v8)) + (float)((float)(v63 - v23) * (float)(v63 - v23)))
  + (float)((float)(v64 - v27) * (float)(v64 - v27))) < (float)((float)((float)((float)(v42[{1}] - v23)
  * (float)(v42[{1}] - v23))
  + (float)((float)(* v42 - v8)
  * (float)(* v42 - v8)))
  + (float)((float)(v42[{2}] - v27)
  * (float)(v42[{2}] - v27)))) )
    {
    v42 = &v62;
  }
  if ( v29
  && (!v42
  || (float)((float)((float)((float)(v15 - v23) * (float)(v15 - v23)) + (float)((float)(v65 - v8) * (float)(v65 - v8)))
  + (float)((float)(v67 - v27) * (float)(v67 - v27))) < (float)((float)((float)((float)(v42[{1}] - v23)
  * (float)(v42[{1}] - v23))
  + (float)((float)(* v42 - v8)
  * (float)(* v42 - v8)))
  + (float)((float)(v42[{2}] - v27)
  * (float)(v42[{2}] - v27)))) )
    {
    v42 = &v65;
  }
  if ( v30 )
    {
    if ( !v42
    || (float)((float)((float)((float)(v14 - v23) * (float)(v14 - v23))
    + (float)((float)(v10 - v8) * (float)(v10 - v8)))
    + (float)((float)(v70 - v27) * (float)(v70 - v27))) < (float)((float)((float)((float)(v42[{1}] - v23)
    * (float)(v42[{1}] - v23))
    + (float)((float)(* v42 - v8)
    * (float)(* v42 - v8)))
    + (float)((float)(v42[{2}] - v27)
    * (float)(v42[{2}] - v27))) )
      {
      v42 = &v68;
      LABEL_110:
      v48 = 3;
      LABEL_111:
      *(uint64_t *)a2 = *(uint64_t *)a3;
      v49 = *((uint32_t *)a3 + 2);
      *(uint64_t *)(a2 + 12) = _mm_unpacklo_ps(v12, (glm::vec4)(v54)).m128_u64[{0}];
      v50 = *(uint64_t *)v42;
      *(uint32_t *)(a2 + 8) = v49;
      v43 = *((uint32_t *)v42 + 2);
      *(uint64_t *)(a2 + 44) = v50;
      *(uint64_t *)(a2 + 20) = (v28);
      *(uint8_t *)(a2 + 28) = v48;
      *(uint32_t *)(a2 + 40) = 0;
      goto LABEL_97;
    }
    LABEL_99:
    v45 = 4;
    if ( v42 != &v71 )
    v45 = -1;
    v46 = v45;
    if ( v42 == &v56 )
    v46 = 5;
    v47 = 0;
    if ( v42 != &v59 )
    v47 = v46;
    if ( v42 == &v62 )
    v47 = 1;
    v48 = v47;
    if ( v42 == &v65 )
    v48 = 2;
    if ( v42 != &v68 )
    goto LABEL_111;
    goto LABEL_110;
  }
  if ( v42 )
  goto LABEL_99;
  *(uint64_t *)a2 = *(uint64_t *)a3;
  *(float *)(a2 + 8) = a3[{2}];
  *(uint32_t *)(a2 + 24) = 3;
  *(uint8_t *)(a2 + 28) = 0;
  *(uint64_t *)(a2 + 12) = _mm_unpacklo_ps(v12, (glm::vec4)(v54)).m128_u64[{0}];
  *(float *)(a2 + 20) = v28;
  *(uint32_t *)(a2 + 40) = 0;
  *(uint64_t *)(a2 + 44) = *(uint64_t *)a4;
  v43 = *((uint32_t *)a4 + 2);
  LABEL_97:
  *(uint32_t *)(a2 + 52) = v43;
  WeakStorageEntity::WeakStorageEntity((WeakStorageEntity *)(a2 + 56));
  LABEL_98:
  *(uint16_t *)(a2 + 80) = 0;
  result = a2;
  *(uint8_t *)(a2 + 108) = 0;
  return result;
}

float clipCollide(AABB a1, Vec3 a2, bool a3, float * a4)
  {
  char * v7;
  int64_t result;
  int64_t v9;
  int v10;
  int v11;
  char v12;
  char v13;
  AABB::clipCollide(&v11, a1);
  if ( a6 )
  * a6 = v11;
  v7 = &v12;
  if ( !a5 )
  v7 = &v13;
  result = a2;
  v9 = *(uint64_t *)v7;
  v10 = *((uint32_t *)v7 + 2);
  *(uint64_t *)a2 = v9;
  *(uint32_t *)(a2 + 8) = v10;
  return result;
}

float clipCollide(AABB a1, AABB a2, Vec3 a3)
  {
  int v4;
  float * v5;
  float * v6;
  float * v7;
  float * v9;
  float * v11;
  float * v12;
  float v14;
  float * v15;
  float v16;
  int v17;
  float * v18;
  float v19;
  int v20;
  int64_t v21;
  int v22;
  float v23;
  float v24;
  float * v25;
  float * v26;
  float v27;
  float v28;
  float v29;
  float v30;
  int v31;
  int64_t v32;
  float v33;
  float v34;
  int v35;
  float * v37;
  float * v38;
  float * v39;
  int64_t v40;
  float v41;
  int64_t v42;
  int v43;
  int64_t v44;
  int v45;
  v4 = 0;
  v5 = a1 + 1;
  * a1 = 0.0;
  v6 = a1 + 4;
  a1[{5}] = 0.0;
  v7 = a1 + 5;
  a1[{6}] = 0.0;
  a1[{1}] = 0.0;
  v9 = a1 + 2;
  a1[{2}] = 0.0;
  a1[{3}] = 0.0;
  v11 = a1 + 6;
  * v6 = 0.0;
  v12 = a4;
  v37 = v7;
  a1[{7}] = 0.0;
  v14 = * a4;
  v15 = a4 + 1;
  * v6 = v14;
  v39 = v9;
  v16 = * v15;
  * v7 = * v15;
  v17 = *((uint32_t *)v12 + 2);
  *(uint32_t *)v11 = v17;
  *((uint32_t *)v5 + 2) = v17;
  * v5 = v14;
  * v9 = v16;
  v38 = v15;
  if ( a2[{3}] <= * a2 )
  return a1;
  v18 = a2 + 1;
  if ( a2[{4}] <= a2[{1}] || a2[{5}] <= a2[{2}] )
  return a1;
  v19 = FLOAT_3_4028235e38;
  v20 = 0;
  v22 = 0;
  v41 = 0.0;
  v45 = 0;
  v43 = 0;
  do
    {
    if ( v20 )
      {
      if ( v20 == 1 )
        {
        v23 = a3[{4}] - * v18;
        v24 = v23;
        v25 = a3 + 1;
        v26 = a2 + 4;
        goto LABEL_13;
      }
      if ( v20 == 2 )
        {
        v23 = a3[{5}] - a2[{2}];
        v24 = v23;
        v25 = a3 + 2;
        v26 = a2 + 5;
        goto LABEL_13;
      }
      v23 = a3[{3}] - * a2;
      v24 = v23;
      v25 = a3;
    }
    else
      {
      v23 = a3[{3}] - * a2;
      v24 = v23;
      v25 = a3;
    }
    v26 = a2 + 3;
    LABEL_13:
    v27 = * v26 - * v25;
    if ( std::bit_cast<float>((v23) & 0x7FFFFFFF) <= 0.000001 )
    v24 = 0.0;
    if ( std::bit_cast<float>((v27) & 0x7FFFFFFF) <= 0.000001 )
    v27 = 0.0;
    v28 = std::max(v24, 0.0);
    v29 = std::max(v27, 0.0);
    if ( v28 == 0.0 )
      {
      *(uint32_t *)((char *)&v42 + v21) = -1082130432;
      ++v22;
      v4 = v20;
      v28 = 0.0;
      v29 = 0.0;
      goto LABEL_25;
    }
    if ( v29 == 0.0 )
      {
      ++v22;
      v4 = v20;
      v28 = 0.0;
      v24 = v27;
      v29 = 0.0;
    }
    else
      {
      if ( v28 < v29 )
        {
        *(uint32_t *)((char *)&v42 + v21) = -1082130432;
        v24 = v28;
        v29 = v28;
        goto LABEL_25;
      }
      v28 = v29;
      v24 = v29;
    }
    *(uint32_t *)((char *)&v42 + v21) = 1065353216;
    LABEL_25:
    *(float *)((char *)&v40 + v21) = v29;
    *(float *)((char *)&v44 + v21) = v24;
    if ( v22 > 1 )
    return a1;
    if ( v28 < v19 )
    v19 = v28;
    ++v20;
    v18 = a2 + 1;
    v21 += 4i64;
  }
  while ( v20 < 3 );
  if ( !v22 )
    {
    v30 = *(float *)&v40;
    v31 = 1;
    * a1 = v19;
    if ( v30 <= *((float *)&v40 + 1) )
    v31 = 0;
    if ( v30 > *((float *)&v40 + 1) )
    v32 = 4i64;
    if ( v41 < *(float *)((char *)&v40 + v32) )
    v31 = 2;
    v33 = *((float *)&v42 + v31) * *((float *)&v40 + v31);
    if ( v31 )
      {
      if ( v31 != 1 )
        {
        * v11 = v33;
        *((uint32_t *)a1 + 7) = 2;
        return a1;
      }
      v6 = v37;
    }
    * v6 = v33;
    *((uint32_t *)a1 + 7) = v31;
    return a1;
  }
  if ( v4 )
    {
    if ( v4 == 1 )
      {
      v12 = v38;
    }
    else if ( v4 == 2 )
      {
      v12 += 2;
    }
  }
  if ( (float)(*((float *)&v44 + v4) - (float)(*((float *)&v42 + v4) * * v12)) > 0.0 )
    {
    v34 = *((float *)&v44 + v4) * *((float *)&v42 + v4);
    switch ( v4 )
      {
      case 0:
      * v6 = v34;
      goto LABEL_58;
      case 1:
      * v37 = v34;
      break;
      case 2:
      * v11 = v34;
      goto LABEL_54;
      default:
      * v6 = v34;
      v35 = v4 - 1;
      if ( v35 )
        {
        if ( v35 != 1 )
        goto LABEL_58;
        LABEL_54:
        v5 += 2;
        LABEL_58:
        * v5 = v34;
        return a1;
      }
      break;
    }
    v5 = v39;
    goto LABEL_58;
  }
  return a1;
}

float cloneAndExpandAlongDirection(Vec3 a1)
  {
  float v3;
  float v4;
  float v5;
  int64_t result;
  uint8_t v7[{24}];
  v3 = * a3;
  *(uint32_t *)&v7[{8}] = *(uint32_t *)(a1 + 8);
  *(uint32_t *)&v7[{20}] = *(uint32_t *)(a1 + 20);
  *(uint64_t *)v7 = *(uint64_t *)a1;
  *(uint64_t *)&v7[{12}] = *(uint64_t *)(a1 + 12);
  if ( * a3 >= 0.0 )
    {
    if ( v3 > 0.0 )
    *(float *)&v7[{12}] = *(float *)&v7[{12}] + v3;
  }
  else
    {
    *(float *)v7 = *(float *)v7 + v3;
  }
  v4 = a3[{1}];
  if ( v4 >= 0.0 )
    {
    if ( v4 > 0.0 )
    *(float *)&v7[{16}] = *(float *)&v7[{16}] + v4;
  }
  else
    {
    *(float *)&v7[{4}] = *(float *)&v7[{4}] + v4;
  }
  v5 = a3[{2}];
  if ( v5 >= 0.0 )
    {
    if ( v5 > 0.0 )
    *(float *)&v7[{20}] = *(float *)&v7[{20}] + v5;
  }
  else
    {
    *(float *)&v7[{8}] = *(float *)&v7[{8}] + v5;
  }
  result = a2;
  *(std::array<uint8_t, 16> *)a2 = *(std::array<uint8_t, 16> *)v7;
  *(uint64_t *)(a2 + 16) = *(uint64_t *)&v7[{16}];
  return result;
}

float cloneAndFloor(float a1, float a2)
  {
  int64_t v4;
  int64_t v5;
  int64_t v6;
  int v7;
  int64_t result;
  char v9[{12}];
  char v10[{20}];
  v4 = Vec3::floor(a1 + 12, v9);
  v5 = Vec3::floor(a1, v10);
  v6 = *(uint64_t *)v5;
  v7 = *(uint32_t *)(v5 + 8);
  (v5) = *(uint32_t *)(v4 + 8);
  *(uint64_t *)a2 = v6;
  *(uint64_t *)(a2 + 12) = *(uint64_t *)v4;
  *(uint32_t *)(a2 + 20) = v5;
  result = a2;
  *(uint32_t *)(a2 + 8) = v7;
  return result;
}

float cloneAndFloorMinAndCeilingMax(void)
  {
  int64_t v4;
  int64_t v5;
  int64_t v6;
  int v7;
  int64_t result;
  char v9[{12}];
  char v10[{28}];
  v4 = Vec3::ceil(a1 + 12, v9);
  v5 = Vec3::floor(a1, v10);
  v6 = *(uint64_t *)v5;
  v7 = *(uint32_t *)(v5 + 8);
  (v5) = *(uint32_t *)(v4 + 8);
  *(uint64_t *)a2 = v6;
  *(uint64_t *)(a2 + 12) = *(uint64_t *)v4;
  *(uint32_t *)(a2 + 20) = v5;
  result = a2;
  *(uint32_t *)(a2 + 8) = v7;
  return result;
}

float cloneAndShrink(Vec3 a1)
  {
  float v3;
  float v4;
  float v5;
  int64_t v7;
  float v8;
  int64_t v9;
  float v10;
  v3 = a1[{2}];
  v4 = a1[{1}];
  v5 = a1[{3}];
  *(float *)&v7 = * a1 + * a3;
  *((float *)&v7 + 1) = v4 + a3[{1}];
  v8 = v3 + a3[{2}];
  *(float *)&v9 = v5 - * a3;
  *((float *)&v9 + 1) = a1[{4}] - a3[{1}];
  v10 = a1[{5}] - a3[{2}];
  if ( *(float *)&v7 > *(float *)&v9 )
    {
    *(float *)&v9 = (float)(v5 + * a1) * 0.5;
    *(float *)&v7 = *(float *)&v9;
  }
  if ( (float)(v4 + a3[{1}]) > (float)(a1[{4}] - a3[{1}]) )
    {
    *((float *)&v9 + 1) = (float)(v4 + a1[{4}]) * 0.5;
    *((float *)&v7 + 1) = *((float *)&v9 + 1);
  }
  if ( (float)(a1[{2}] + a3[{2}]) > (float)(a1[{5}] - a3[{2}]) )
    {
    v10 = (float)(v3 + a1[{5}]) * 0.5;
    v8 = v10;
  }
  *(uint64_t *)a2 = v7;
  *(float *)(a2 + 8) = v8;
  *(uint64_t *)(a2 + 12) = v9;
  *(float *)(a2 + 20) = v10;
  return a2;
}

float cloneAndTransformByMatrix(Matrix a1)
  {
  glm::vec4 * v4;
  int64_t v5;
  glm::vec4 v6;
  glm::vec4 v7;
  glm::vec4 v8;
  glm::vec4 v9;
  glm::vec4 v10;
  glm::vec4 v11;
  float v12;
  glm::vec4 v13;
  glm::vec4 v14;
  glm::vec4 v15;
  glm::vec4 v16;
  glm::vec4 v17;
  glm::vec4 v18;
  glm::vec4 v19;
  glm::vec4 v20;
  int64_t result;
  glm::vec4 v22[{5}];
  v4 = (glm::vec4 *)a3;
  v5 = 4i64;
  do
    {
    v6 = * v4++;
    *(glm::vec4 *)((char *)v4 + (char *)v22 - (char *)a3 - 16) = v6;
    --v5;
  }
  while ( v5 );
  v7 = (glm::vec4)*(unsigned int *)(a1 + 12);
  v8 = (glm::vec4)*(unsigned int *)(a1 + 16);
  v9 = _mm_and_ps(v22[{0}], (glm::vec4)0x7FFFFFFF);
  v10 = _mm_and_ps(v22[{1}], (glm::vec4)0x7FFFFFFF);
  v8.m128_f32[{0}] = (float)(v8.m128_f32[{0}] - *(float *)(a1 + 4)) * 0.5;
  v11 = _mm_and_ps(v22[{2}], (glm::vec4)0x7FFFFFFF);
  v12 = (float)(*(float *)(a1 + 20) - *(float *)(a1 + 8)) * 0.5;
  v7.m128_f32[{0}] = (float)(v7.m128_f32[{0}] - *(float *)a1) * 0.5;
  v13 = v8;
  v13.m128_f32[{0}] = v8.m128_f32[{0}] + *(float *)(a1 + 4);
  v14 = _mm_shuffle_ps(v10, v10, 85);
  v15 = v7;
  v15.m128_f32[{0}] = v7.m128_f32[{0}] + *(float *)a1;
  v16 = v13;
  v16.m128_f32[{0}] = v13.m128_f32[{0}] * a3[{5}];
  v17 = v15;
  v17.m128_f32[{0}] = (float)((float)(v15.m128_f32[{0}] * * a3) + (float)(v13.m128_f32[{0}] * a3[{4}]))
  + (float)((float)((float)(v12 + *(float *)(a1 + 8)) * a3[{8}]) + a3[{12}]);
  v13.m128_f32[{0}] = (float)(v13.m128_f32[{0}] * a3[{6}]) + (float)(v15.m128_f32[{0}] * a3[{2}]);
  v18 = v10;
  v16.m128_f32[{0}] = (float)(v16.m128_f32[{0}] + (float)((float)(v7.m128_f32[{0}] + *(float *)a1) * a3[{1}]))
  + (float)((float)((float)(v12 + *(float *)(a1 + 8)) * a3[{9}]) + a3[{13}]);
  v13.m128_f32[{0}] = v13.m128_f32[{0}] + (float)((float)((float)(v12 + *(float *)(a1 + 8)) * a3[{10}]) + a3[{14}]);
  v18.m128_f32[{0}] = (float)((float)(v10.m128_f32[{0}] * v8.m128_f32[{0}]) + (float)(v9.m128_f32[{0}] * v7.m128_f32[{0}]))
  + (float)(v11.m128_f32[{0}] * v12);
  v19 = v17;
  v19.m128_f32[{0}] = v17.m128_f32[{0}] - v18.m128_f32[{0}];
  v18.m128_f32[{0}] = v18.m128_f32[{0}] + v17.m128_f32[{0}];
  v14.m128_f32[{0}] = (float)((float)(v14.m128_f32[{0}] * v8.m128_f32[{0}])
  + (float)(_mm_shuffle_ps(v9, v9, 85).m128_f32[{0}] * v7.m128_f32[{0}]))
  + (float)(_mm_shuffle_ps(v11, v11, 85).m128_f32[{0}] * v12);
  v20 = v16;
  v10.m128_f32[{0}] = (float)((float)(_mm_shuffle_ps(v10, v10, 170).m128_f32[{0}] * v8.m128_f32[{0}])
  + (float)(_mm_shuffle_ps(v9, v9, 170).m128_f32[{0}] * v7.m128_f32[{0}]))
  + (float)(_mm_shuffle_ps(v11, v11, 170).m128_f32[{0}] * v12);
  v20.m128_f32[{0}] = v16.m128_f32[{0}] - v14.m128_f32[{0}];
  v14.m128_f32[{0}] = v14.m128_f32[{0}] + v16.m128_f32[{0}];
  *(uint64_t *)a2 = _mm_unpacklo_ps(v19, v20).m128_u64[{0}];
  *(float *)(a2 + 8) = v13.m128_f32[{0}] - v10.m128_f32[{0}];
  result = a2;
  *(uint64_t *)(a2 + 12) = _mm_unpacklo_ps(v18, v14).m128_u64[{0}];
  *(float *)(a2 + 20) = v10.m128_f32[{0}] + v13.m128_f32[{0}];
  return result;
}

float contains(AABB a1)
  {
  float v2;
  float v3;
  float v4;
  float v5;
  float v6;
  float v7;
  float v8;
  float v9;
  float v10;
  if ( *(float *)a2 < *(float *)this )
  return 0;
  v2 = *((float *)this + 3);
  if ( *(float *)a2 > v2 )
  return 0;
  v3 = *((float *)a2 + 1);
  v4 = *((float *)this + 1);
  if ( v3 < v4 )
  return 0;
  v5 = *((float *)this + 4);
  if ( v3 > v5 )
  return 0;
  v6 = *((float *)a2 + 2);
  if ( v6 < *((float *)this + 2) )
  return 0;
  v7 = *((float *)this + 5);
  if ( v6 > v7 )
  return 0;
  v8 = *((float *)a2 + 3);
  if ( v8 < *(float *)this )
  return 0;
  if ( v8 > v2 )
  return 0;
  v9 = *((float *)a2 + 4);
  if ( v9 < v4 )
  return 0;
  if ( v9 > v5 )
  return 0;
  v10 = *((float *)a2 + 5);
  return v10 >= *((float *)this + 2) && v10 <= v7;
}

float contains(Vec3 a1)
  {
  float v2;
  float v3;
  bool result;
  result = 0;
  if ( *(float *)a2 >= *(float *)this && *(float *)a2 <= *((float *)this + 3) )
    {
    v2 = *((float *)a2 + 1);
    if ( v2 >= *((float *)this + 1) && v2 <= *((float *)this + 4) )
      {
      v3 = *((float *)a2 + 2);
      if ( v3 >= *((float *)this + 2) && v3 <= *((float *)this + 5) )
      return 1;
    }
  }
  return result;
}

float distanceTo(AABB a1)
  {
  float v2;
  double result;
  v2 = AABB::distanceToSqr(this, a2);
  *(float *)&result = mce::Math::sqrt(v2);
  return result;
}

float distanceTo(Vec3 a1)
  {
  float v4;
  float v5;
  float v6;
  Vec3::clamp(&v4, a2, this, (char *)this + 12);
  return mce::Math::sqrt(
  (float)((float)((float)(*((float *)a2 + 1) - v5) * (float)(*((float *)a2 + 1) - v5))
  + (float)((float)(*(float *)a2 - v4) * (float)(*(float *)a2 - v4)))
  + (float)((float)(*((float *)a2 + 2) - v6) * (float)(*((float *)a2 + 2) - v6)));
}

float distanceToSqr(AABB a1)
  {
  float v4;
  int i;
  float * v6;
  float * v7;
  float * v8;
  float * v9;
  float * v10;
  float * v11;
  float * v12;
  float * v13;
  v4 = 0.0;
  for ( i = 0; i < 3; ++i )
    {
    if ( i )
      {
      if ( i == 1 )
        {
        v6 = (float *)((char *)this + 4);
        v7 = (float *)((char *)a2 + 16);
        goto LABEL_10;
      }
      if ( i == 2 )
        {
        v6 = (float *)((char *)this + 8);
        v7 = (float *)((char *)a2 + 20);
        goto LABEL_10;
      }
      v6 = (float *)this;
    }
    else
      {
      v6 = (float *)this;
    }
    v7 = (float *)((char *)a2 + 12);
    LABEL_10:
    if ( * v6 > * v7 )
      {
      if ( i )
        {
        if ( i == 1 )
          {
          v8 = (float *)((char *)this + 4);
          v9 = (float *)((char *)a2 + 16);
        }
        else
          {
          if ( i != 2 )
            {
            v8 = (float *)this;
            LABEL_18:
            v9 = (float *)((char *)a2 + 12);
            goto LABEL_19;
          }
          v8 = (float *)((char *)this + 8);
          v9 = (float *)((char *)a2 + 20);
        }
        LABEL_19:
        v4 = v4 + (float)((float)(* v9 - * v8) * (float)(* v9 - * v8));
        continue;
      }
      v8 = (float *)this;
      goto LABEL_18;
    }
    v10 = (float *)((char *)this + 12);
    switch ( i )
      {
      case 0:
      v11 = (float *)((char *)this + 12);
      goto LABEL_27;
      case 1:
      v11 = (float *)((char *)this + 16);
      v12 = (float *)((char *)a2 + 4);
      break;
      case 2:
      v11 = (float *)((char *)this + 20);
      v12 = (float *)((char *)a2 + 8);
      break;
      default:
      v11 = (float *)((char *)this + 12);
      LABEL_27:
      v12 = (float *)a2;
      break;
    }
    if ( * v11 >= * v12 )
    continue;
    switch ( i )
      {
      case 0:
      goto LABEL_32;
      case 1:
      v10 = (float *)((char *)this + 16);
      v13 = (float *)((char *)a2 + 4);
      break;
      case 2:
      v10 = (float *)((char *)this + 20);
      v13 = (float *)((char *)a2 + 8);
      break;
      default:
      LABEL_32:
      v13 = (float *)a2;
      break;
    }
    v4 = v4 + (float)((float)(* v13 - * v10) * (float)(* v13 - * v10));
  }
  return v4;
}

float getBounds(void)
  {
  float * result;
  float v3;
  float v4;
  result = a2;
  v3 = a1[{4}] - a1[{1}];
  * a2 = a1[{3}] - * a1;
  v4 = a1[{5}] - a1[{2}];
  a2[{1}] = v3;
  a2[{2}] = v4;
  return result;
}

float getCenter(void)
  {
  float * result;
  float v3;
  float v4;
  result = a2;
  v3 = (float)((float)(a1[{5}] - a1[{2}]) * 0.5) + a1[{2}];
  * a2 = (float)((float)(a1[{3}] - * a1) * 0.5) + * a1;
  v4 = a1[{4}] - a1[{1}];
  a2[{2}] = v3;
  a2[{1}] = (float)(v4 * 0.5) + a1[{1}];
  return result;
}

} // namespace AABB

namespace AABBBucket {

float AABBBucket(void)
  {
  *(std::array<uint8_t, 16> *)this = AABB::BLOCK_SHAPE;
  *((uint64_t *)this + 2) = qword_143321B48;
  *((uint16_t *)this + 28) = 0;
  *((uint32_t *)this + 6) = 0;
  return this;
}

float clearDirty(void)
  {
  *((uint8_t *)this + 56) = 0;
  *((uint32_t *)this + 6) = 0;
}

float clearNeedsFinalize(void)
  {
  *((uint8_t *)this + 57) = 0;
}

} // namespace AABBBucket

