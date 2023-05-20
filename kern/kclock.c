/* See COPYRIGHT for copyright information. */

#include <inc/x86.h>
#include <kern/kclock.h>
#include <kern/timer.h>
#include <kern/trap.h>
#include <kern/picirq.h>
#include <kern/timer.h>
#include <inc/time.h>

uint8_t
cmos_read8(uint8_t reg) {
    outb(CMOS_CMD, reg | CMOS_NMI_LOCK);
    uint8_t res = inb(CMOS_DATA);

    nmi_enable();
    return res;
}

void
cmos_write8(uint8_t reg, uint8_t value) {
    outb(CMOS_CMD, reg | CMOS_NMI_LOCK);
    outb(CMOS_DATA, value);

    nmi_enable();
}

uint16_t
cmos_read16(uint8_t reg) {
    return cmos_read8(reg) | (cmos_read8(reg + 1) << 8);
}

static void
rtc_timer_pic_interrupt(void) {
    pic_irq_unmask(IRQ_CLOCK);
}

static void
rtc_timer_pic_handle(void) {
    rtc_check_status();
    pic_send_eoi(IRQ_CLOCK);
}

struct Timer timer_rtc = {
        .timer_name = "rtc",
        .timer_init = rtc_timer_init,
        .enable_interrupts = rtc_timer_pic_interrupt,
        .handle_interrupts = rtc_timer_pic_handle,
};

static int
get_time(void) {
    struct tm time;

    uint8_t s, m, h, d, M, y, Y, state;
    s = cmos_read8(RTC_SEC);
    m = cmos_read8(RTC_MIN);
    h = cmos_read8(RTC_HOUR);
    d = cmos_read8(RTC_DAY);
    M = cmos_read8(RTC_MON);
    y = cmos_read8(RTC_YEAR);
    Y = cmos_read8(RTC_YEAR_HIGH);
    state = cmos_read8(RTC_BREG);

    if (state & RTC_12H) {
        /* Fixup 12 hour mode */
        h = (h & 0x7F) + 12 * !!(h & 0x80);
    }

    if (!(state & RTC_BINARY)) {
        /* Fixup binary mode */
        s = BCD2BIN(s);
        m = BCD2BIN(m);
        h = BCD2BIN(h);
        d = BCD2BIN(d);
        M = BCD2BIN(M);
        y = BCD2BIN(y);
        Y = BCD2BIN(Y);
    }

    time.tm_sec = s;
    time.tm_min = m;
    time.tm_hour = h;
    time.tm_mday = d;
    time.tm_mon = M - 1;
    time.tm_year = y + Y * 100 - 1900;

    return timestamp(&time);
}

int
gettime(void) {
    // LAB 12: your code here
    int res = 0;


    return res;
}

void
rtc_timer_init(void) {
    uint8_t regb_value = cmos_read8(RTC_BREG);
    regb_value |= RTC_PIE;
    cmos_write8(RTC_BREG, regb_value);

    uint8_t rega_value = cmos_read8(RTC_AREG);
    rega_value = RTC_SET_NEW_RATE(rega_value, RTC_500MS_RATE);
    cmos_write8(RTC_AREG, rega_value);
}

uint8_t
rtc_check_status(void) {
    return cmos_read8(RTC_CREG);
}
