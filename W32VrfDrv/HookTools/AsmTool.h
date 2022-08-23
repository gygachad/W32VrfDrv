#pragma once

//Снять защиту записи на страницы памяти
void 
__stdcall 
__clear_wp(void);

//Восстановить защиту записи памяти
void 
__stdcall 
__set_wp(void);

//Включить прерывания
void
__stdcall
__enable_interrupt(void);

//выключить прерывания
void
__stdcall
__disable_interrupt(void);