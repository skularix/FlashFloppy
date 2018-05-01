/*
 * eadf.c
 * 
 * Extended Amiga Disk File (EADF) files.
 * 
 * Written & released by Keir Fraser <keir.xen@gmail.com>
 * 
 * This is free and unencumbered software released into the public domain.
 * See the file COPYING for more details, or visit <http://unlicense.org>.
 */

/* Amiga writes short bitcells (PAL: 14/7093790 us) hence long tracks. 
 * For better loader compatibility it is sensible to emulate this. */
#define DD_TRACKLEN_BC 101376 /* multiple of 32 */
#define POST_IDX_GAP_BC 1024

/* Shift even/odd bits into MFM data-bit positions */
#define even(x) ((x)>>1)
#define odd(x) (x)

static uint32_t amigados_checksum(void *dat, unsigned int bytes)
{
    uint32_t *p = dat, csum = 0;
    unsigned int i;
    for (i = 0; i < bytes/4; i++)
        csum ^= be32toh(p[i]);
    csum ^= csum >> 1;
    csum &= 0x55555555u;
    return csum;
}

static bool_t eadf_open(struct image *im)
{
    char sig[8];
    uint16_t header[2];

    F_read(&im->fp, sig, sizeof(sig), NULL);
    if (!strncmp(sig, "UAE--ADF", 8)) {
        im->eadf.type = 1;
        im->nr_cyls = 80;
    } else if (!strncmp(sig, "UAE-1ADF", 8)) {
        im->eadf.type = 2;
        F_read(&im->fp, header, sizeof(header));
        im->nr_cyls = be16toh(header[1]) / 2;
    } else {
        return FALSE;
    }

    im->nr_sides = 2;
    printk("EADF: %u cyls, %u sides\n", im->nr_cyls, im->nr_sides);

    return TRUE;
}

static void eadf_seek_track(
    struct image *im, uint16_t track, unsigned int cyl, unsigned int side)
{
    F_lseek(&im->fp, (im->eadf.type == 1) ? 8 + track*4 : 16 + track*12);
    F_read(&im->fp, header, sizeof(header), NULL);
    if (im->eadf.type == 1) {
        im->eadf.trk_len = be16toh(header.type);
        im->eadf.trk_type = !!header.reserved;
        im->tracklen_bc = im->eadf.trk_len * 8;
    } else {
        im->eadf.trk_len = be32toh(header.len);
        im->eadf.trk_type = be16toh(header.type);
        im->tracklen_bc = be32toh(header.bitlen);
    }

    switch (im->eadf.trk_type) {
    case 0:
    }
}

static void eadf_setup_track(
    struct image *im, uint16_t track, uint32_t *start_pos)
{
    struct image_buf *rd = &im->bufs.read_data;
    struct image_buf *bc = &im->bufs.read_bc;
    uint32_t decode_off, sector, sys_ticks = start_pos ? *start_pos : 0;
    uint8_t cyl = track/2, side = track&1;

    /* TODO: Fake out unformatted tracks. */
    cyl = min_t(uint8_t, cyl, im->nr_cyls-1);
    side = min_t(uint8_t, side, im->nr_sides-1);
    track = cyl*2 + side;

    if (track != im->cur_track)
        eadf_seek_track(im, track, cyl, side);

    im->eadf.trk_len = im->eadf.nr_secs * 512;
    im->eadf.trk_off = track * im->eadf.trk_len;
    im->ticks_since_flux = 0;
    im->cur_track = track;

    im->cur_bc = (sys_ticks * 16) / im->ticks_per_cell;
    if (im->cur_bc >= im->tracklen_bc)
        im->cur_bc = 0;
    im->cur_ticks = im->cur_bc * im->ticks_per_cell;

    decode_off = im->cur_bc;
    if (decode_off < POST_IDX_GAP_BC) {
        im->eadf.decode_pos = 0;
        im->eadf.trk_pos = 0;
    } else {
        decode_off -= POST_IDX_GAP_BC;
        sector = decode_off / (544*16);
        decode_off %= 544*16;
        im->eadf.decode_pos = sector + 1;
        im->eadf.trk_pos = sector * 512;
        if (im->eadf.trk_pos >= im->eadf.trk_len)
            im->eadf.trk_pos = 0;
    }

    rd->prod = rd->cons = 0;
    bc->prod = bc->cons = 0;

    if (start_pos) {
        image_read_track(im);
        bc->cons = decode_off;
    }
}

static bool_t eadf_read_track(struct image *im)
{
    const UINT sec_sz = 512;
    struct image_buf *rd = &im->bufs.read_data;
    struct image_buf *bc = &im->bufs.read_bc;
    uint32_t *buf = rd->p;
    uint32_t pr, *bc_b = bc->p;
    uint32_t bc_len, bc_mask, bc_space, bc_p, bc_c;
    unsigned int i;

    if (rd->prod == rd->cons) {
        F_lseek(&im->fp, im->eadf.trk_off + im->eadf.trk_pos);
        F_read(&im->fp, buf, sec_sz, NULL);
        rd->prod++;
        im->eadf.trk_pos += sec_sz;
        if (im->eadf.trk_pos >= im->eadf.trk_len)
            im->eadf.trk_pos = 0;
    }

    /* Generate some MFM if there is space in the raw-bitcell ring buffer. */
    bc_p = bc->prod / 32; /* MFM longs */
    bc_c = bc->cons / 32; /* MFM longs */
    bc_len = bc->len / 4; /* MFM longs */
    bc_mask = bc_len - 1;
    bc_space = bc_len - (uint16_t)(bc_p - bc_c);

    pr = be32toh(bc_b[(bc_p-1) & bc_mask]);
#define emit_raw(r) ({                                   \
    uint32_t _r = (r);                                   \
    bc_b[bc_p++ & bc_mask] = htobe32(_r & ~(pr << 31));  \
    pr = _r; })
#define emit_long(l) ({                                         \
    uint32_t _l = (l);                                          \
    _l &= 0x55555555u; /* data bits */                          \
    _l |= (~((l>>2)|l) & 0x55555555u) << 1; /* clock bits */    \
    emit_raw(_l); })

    if (im->eadf.decode_pos == 0) {

        /* Post-index track gap */
        if (bc_space < POST_IDX_GAP_BC/32)
            return FALSE;
        for (i = 0; i < POST_IDX_GAP_BC/32; i++)
            emit_long(0);

    } else if (im->eadf.decode_pos == im->eadf.nr_secs+1) {

        /* Pre-index track gap */
        if (bc_space < im->eadf.pre_idx_gap_bc/32)
            return FALSE;
        for (i = 0; i < im->eadf.pre_idx_gap_bc/32-1; i++)
            emit_long(0);
        emit_raw(0xaaaaaaa0); /* write splice */
        im->eadf.decode_pos = -1;

    } else {

        uint32_t info, csum, sector = im->eadf.decode_pos - 1;

        if (bc_space < (544*16)/32)
            return FALSE;

        /* Sector header */

        /* sector gap */
        emit_long(0);
        /* sync */
        emit_raw(0x44894489);
        /* info word */
        info = ((0xff << 24)
                | (im->cur_track << 16)
                | (sector << 8)
                | (im->eadf.nr_secs - sector));
        emit_long(even(info));
        emit_long(odd(info));
        /* label */
        for (i = 0; i < 8; i++)
            emit_long(0);
        /* header checksum */
        csum = info ^ (info >> 1);
        emit_long(0);
        emit_long(odd(csum));
        /* data checksum */
        csum = amigados_checksum(buf, 512);
        emit_long(0);
        emit_long(odd(csum));

        /* Sector data */

        for (i = 0; i < 512/4; i++)
            emit_long(even(be32toh(buf[i])));
        for (i = 0; i < 512/4; i++)
            emit_long(odd(be32toh(buf[i])));
        rd->cons++;

    }

    im->eadf.decode_pos++;
    bc->prod = bc_p * 32;

    return TRUE;
}

static void write_batch(struct image *im, unsigned int sect, unsigned int nr)
{
    uint32_t *wrbuf = im->bufs.write_data.p;
    time_t t;

    if (nr == 0)
        return;

    t = time_now();
    printk("Write %u/%u-%u... ", im->cur_track, sect, sect+nr-1);
    F_lseek(&im->fp, im->eadf.trk_off + sect*512);
    F_write(&im->fp, wrbuf, 512*nr, NULL);
    printk("%u us\n", time_diff(t, time_now()) / TIME_MHZ);
}

static bool_t eadf_write_track(struct image *im)
{
    bool_t flush;
    struct write *write = get_write(im, im->wr_cons);
    struct image_buf *wr = &im->bufs.write_bc;
    uint32_t *buf = wr->p;
    unsigned int bufmask = (wr->len / 4) - 1;
    uint32_t *w, *wrbuf = im->bufs.write_data.p;
    uint32_t c = wr->cons / 32, p = wr->prod / 32;
    uint32_t info, dsum, csum;
    unsigned int i, sect, batch_sect, batch, max_batch;

    /* If we are processing final data then use the end index, rounded up. */
    barrier();
    flush = (im->wr_cons != im->wr_bc);
    if (flush)
        p = (write->bc_end + 31) / 32;

    batch = batch_sect = 0;
    max_batch = im->bufs.write_data.len / 512;
    w = wrbuf;

    while ((int16_t)(p - c) >= (542/2)) {

        /* Scan for sync word. */
        if (be32toh(buf[c++ & bufmask]) != 0x44894489)
            continue;

        /* Info word (format,track,sect,sect_to_gap). */
        info = (buf[c++ & bufmask] & 0x55555555) << 1;
        info |= buf[c++ & bufmask] & 0x55555555;
        csum = info ^ (info >> 1);
        info = be32toh(info);
        sect = (uint8_t)(info >> 8);

        /* Label area. Scan for header checksum only. */
        for (i = 0; i < 8; i++)
            csum ^= buf[c++ & bufmask];
        csum &= 0x55555555;

        /* Header checksum. */
        csum ^= (buf[c++ & bufmask] & 0x55555555) << 1;
        csum ^= buf[c++ & bufmask] & 0x55555555;
        csum = be32toh(csum);

        /* Check the info word and header checksum.  */
        if (((info>>16) != ((0xff<<8) | im->cur_track))
            || (sect >= im->eadf.nr_secs) || (csum != 0)) {
            printk("Bad header: info=%08x csum=%08x\n", info, csum);
            continue;
        }

        if (batch && ((sect != batch_sect + batch) || (batch >= max_batch))) {
            ASSERT(batch <= max_batch);
            write_batch(im, batch_sect, batch);
            batch = 0;
            w = wrbuf;
        }

        /* Data checksum. */
        csum = (buf[c++ & bufmask] & 0x55555555) << 1;
        csum |= buf[c++ & bufmask] & 0x55555555;

        /* Data area. Decode to a write buffer and keep a running checksum. */
        dsum = 0;
        for (i = dsum = 0; i < 128; i++) {
            uint32_t o = buf[(c + 128) & bufmask] & 0x55555555;
            uint32_t e = buf[c++ & bufmask] & 0x55555555;
            dsum ^= o ^ e;
            *w++ = (e << 1) | o;
        }
        c += 128;

        /* Validate the data checksum. */
        csum = be32toh(csum ^ dsum);
        if (csum != 0) {
            printk("Bad data: csum=%08x\n", csum);
            continue;
        }

        /* All good: add to the write-out batch. */
        if (batch++ == 0)
            batch_sect = sect;
    }

    write_batch(im, batch_sect, batch);

    wr->cons = c * 32;

    return flush;
}

const struct image_handler eadf_image_handler = {
    .open = eadf_open,
    .setup_track = eadf_setup_track,
    .read_track = eadf_read_track,
    .rdata_flux = bc_rdata_flux,
    .write_track = eadf_write_track,
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "Linux"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
