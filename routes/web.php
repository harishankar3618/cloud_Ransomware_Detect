<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\MalwareDetectionController;


Route::get('/', [MalwareDetectionController::class, 'welcome'])->name('malware.detect');
Route::post('/', [MalwareDetectionController::class, 'detectMalware']);
Route::post('/ip-scan', [MalwareDetectionController::class, 'scanIp'])->name('ip.scan');
