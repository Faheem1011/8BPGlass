#pragma once

#include <Vector/Vectors.h>
#include <imgui/imgui.h>

#include "resources.h"

using namespace ImGui;
using namespace std;

#include "include/includes.h"

#include "8bp.h"
#include "8bp/Ruleset.h"
#include "imgui/inc/8bp.h"
#include "keylogin.h"
#include "oxorany/oxorany.h"

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES3/gl3.h>

struct MenuState {
    bool isOpen = false;
    int currentTab = 0;
    float sidebarWidth = 300.0f;
    float animProgress = 0.0f;
    float menuAlpha = 0.0f;
    float menuScale = 0.9f;
    ImVec4 accentColor = ImVec4(0.35f, 0.65f, 0.95f, 1.0f);
};
static MenuState g_menu;

static float EaseOutBack(float x) {
    const float c1 = 1.70158f;
    const float c3 = c1 + 1.0f;
    return 1.0f + c3 * powf(x - 1.0f, 3.0f) + c1 * powf(x - 1.0f, 2.0f);
}

static float EaseOutQuart(float x) {
    return 1.0f - powf(1.0f - x, 4.0f);
}

static void DrawGradientRect(ImDrawList* dl, ImVec2 p1, ImVec2 p2, ImU32 col1, ImU32 col2, bool horizontal = true) {
    if (horizontal) {
        dl->AddRectFilledMultiColor(p1, p2, col1, col2, col2, col1);
    } else {
        dl->AddRectFilledMultiColor(p1, p2, col1, col1, col2, col2);
    }
}

static bool SidebarButton(const char* label, const char* icon, bool selected, float width) {
    ImGuiWindow* window = GetCurrentWindow();
    if (window->SkipItems) return false;

    ImGuiContext& g = *GImGui;
    const ImGuiStyle& style = g.Style;
    const ImGuiID id = window->GetID(label);

    ImVec2 pos = window->DC.CursorPos;
    ImVec2 size = ImVec2(width - 20.0f, 58.0f);

    const ImRect bb(pos, pos + size);
    ItemSize(size, style.FramePadding.y);
    if (!ItemAdd(bb, id)) return false;

    bool hovered, held;
    bool pressed = ButtonBehavior(bb, id, &hovered, &held);

    static std::map<ImGuiID, float> hoverAnim;
    float& animT = hoverAnim[id];
    float targetT = (selected || hovered) ? 1.0f : 0.0f;
    animT += (targetT - animT) * g.IO.DeltaTime * 12.0f;

    ImDrawList* dl = window->DrawList;
    
    if (selected) {
        ImU32 gradCol1 = IM_COL32(40, 100, 180, 255);
        ImU32 gradCol2 = IM_COL32(60, 130, 200, 255);
        dl->AddRectFilled(bb.Min, bb.Max, gradCol1, 10.0f);
        dl->AddRectFilled(ImVec2(bb.Min.x, bb.Min.y + 2), ImVec2(bb.Min.x + 6, bb.Max.y - 2), IM_COL32(100, 200, 255, 255), 3.0f);
    } else if (animT > 0.01f) {
        ImU32 hoverCol = IM_COL32(50, 50, 60, (int)(180 * animT));
        dl->AddRectFilled(bb.Min, bb.Max, hoverCol, 12.0f);
    }

    float iconOffset = 8.0f * animT;
    ImVec2 iconPos = ImVec2(bb.Min.x + 22.0f + iconOffset, bb.Min.y + (size.y - g.FontSize) * 0.5f);
    dl->AddText(iconPos, selected ? IM_COL32(255, 255, 255, 255) : IM_COL32(140, 140, 160, (int)(180 + 75 * animT)), icon);
    
    ImVec2 textPos = ImVec2(bb.Min.x + 58.0f + iconOffset, bb.Min.y + (size.y - g.FontSize) * 0.5f);
    dl->AddText(textPos, selected ? IM_COL32(255, 255, 255, 255) : IM_COL32(200, 200, 215, (int)(200 + 55 * animT)), label);

    return pressed;
}

static bool ToggleSwitch(const char* label, bool* v) {
    ImGuiWindow* window = GetCurrentWindow();
    if (window->SkipItems) return false;

    ImGuiContext& g = *GImGui;
    const ImGuiStyle& style = g.Style;
    const ImGuiID id = window->GetID(label);

    float height = 32.0f;
    float width = 56.0f;
    float radius = height * 0.5f;

    ImVec2 textSize = CalcTextSize(label);
    ImVec2 pos = window->DC.CursorPos;
    ImVec2 size = ImVec2(GetContentRegionAvail().x, ImMax(height, textSize.y) + style.FramePadding.y * 2 + 10.0f);

    const ImRect bb(pos, pos + size);
    ItemSize(size, style.FramePadding.y);
    if (!ItemAdd(bb, id)) return false;

    bool hovered, held;
    bool pressed = ButtonBehavior(bb, id, &hovered, &held);
    if (pressed) *v = !*v;

    static std::map<ImGuiID, float> switchAnim;
    float& animT = switchAnim[id];
    float targetT = *v ? 1.0f : 0.0f;
    animT += (targetT - animT) * g.IO.DeltaTime * 14.0f;

    ImDrawList* dl = window->DrawList;
    
    if (hovered) {
        dl->AddRectFilled(bb.Min, bb.Max, IM_COL32(45, 45, 55, 100), 10.0f);
    }
    
    ImVec2 togglePos = ImVec2(bb.Max.x - width - 15.0f, bb.Min.y + (size.y - height) * 0.5f);
    ImVec2 toggleEnd = ImVec2(togglePos.x + width, togglePos.y + height);
    
    ImVec4 offColor = ImVec4(0.27f, 0.27f, 0.31f, 1.0f);
    ImVec4 onColor = ImVec4(0.20f, 0.55f, 0.86f, 1.0f);
    ImVec4 bgColorV = ImLerp(offColor, onColor, animT);
    dl->AddRectFilled(togglePos, toggleEnd, ImColor(bgColorV), radius);
    
    float knobX = togglePos.x + radius + (width - height) * animT;
    float knobY = togglePos.y + radius;
    float knobR = radius - 4.0f;
    
    dl->AddCircleFilled(ImVec2(knobX, knobY), knobR + 2.0f, IM_COL32(0, 0, 0, 40));
    dl->AddCircleFilled(ImVec2(knobX, knobY), knobR, IM_COL32(255, 255, 255, 255));

    dl->AddText(ImVec2(bb.Min.x + 15.0f, bb.Min.y + (size.y - textSize.y) * 0.5f), IM_COL32(230, 230, 240, 255), label);

    return pressed;
}

INLINE void DrawAutoQueue() {
    if (!g_Token.empty() && !g_Auth.empty() && g_Token == g_Auth) {
        static std::chrono::steady_clock::time_point last_call_time;
        static std::chrono::steady_clock::time_point countdown_start;
        static bool counting = false;

        auto now = std::chrono::steady_clock::now();

        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_call_time).count() > 500) {
            counting = false;
        }
        last_call_time = now;

        if (!counting) {
            counting = true;
            countdown_start = now;
        }

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - countdown_start).count();
        int remaining_ms = 3000 - elapsed;

        if (remaining_ms <= 0) {
            if (sharedMenuManager.getMenuStateId() == 13) PopMenuState(13);
            StartLastMatch();
            counting = false;
            return;
        }

        SetNextWindowPos(ImVec2(Width / 2.0f, Height / 2.0f), ImGuiCond_Always, ImVec2(0.5f, 0.5f));
        SetNextWindowSize(ImVec2(360, 260), ImGuiCond_Always);
        PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.10f, 0.10f, 0.12f, 0.98f));
        PushStyleVar(ImGuiStyleVar_WindowRounding, 20.0f);

        if (Begin(O("##AutoQueue"), nullptr, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings)) {
            ImDrawList* dl = GetWindowDrawList();
            ImVec2 winPos = GetWindowPos();
            ImVec2 winSize = GetWindowSize();
            
            DrawGradientRect(dl, winPos, ImVec2(winPos.x + winSize.x, winPos.y + 70), IM_COL32(40, 100, 180, 255), IM_COL32(60, 140, 200, 255), true);
            dl->AddRectFilled(winPos, ImVec2(winPos.x + winSize.x, winPos.y + 20), IM_COL32(40, 100, 180, 255), 20.0f, ImDrawFlags_RoundCornersTop);
            
            ImVec2 titleSize = CalcTextSize(O("Auto Queue"));
            dl->AddText(ImVec2(winPos.x + (winSize.x - titleSize.x) * 0.5f, winPos.y + 22), IM_COL32(255, 255, 255, 255), O("Auto Queue"));

            SetCursorPosY(90);
            float font_scale = 3.5f;
            SetWindowFontScale(font_scale);

            std::string count_str = std::to_string((remaining_ms / 1000) + 1);
            auto text_size = CalcTextSize(count_str.c_str());
            SetCursorPosX((winSize.x - text_size.x) * 0.5f);
            TextColored(ImVec4(0.35f, 0.7f, 1.0f, 1.0f), "%s", count_str.c_str());

            SetWindowFontScale(1.0f);

            SetCursorPosY(winSize.y - 75);
            SetCursorPosX(25);
            PushStyleColor(ImGuiCol_Button, ImVec4(0.75f, 0.25f, 0.25f, 1.0f));
            PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.85f, 0.35f, 0.35f, 1.0f));
            PushStyleVar(ImGuiStyleVar_FrameRounding, 12.0f);
            
            if (Button(O("Cancel"), ImVec2(winSize.x - 50, 50))) {
                persistent_bool[O("bAutoQueue")] = false;
                counting = false;
            }
            
            PopStyleVar();
            PopStyleColor(2);
            End();
        }
        PopStyleVar();
        PopStyleColor();
    }
}

INLINE void DrawESP(ImDrawList* draw) {
    if (!g_Token.empty() && !g_Auth.empty() && g_Token == g_Auth) {
        if (!sharedGameManager) return;

        UpdateScreenTable();

        sharedDirector = F(ptr, libmain + O(0x4f06288));
        if (!sharedDirector) return;

        sharedUserInfo = F(ptr, libmain + O(0x4e9feb8));
        if (!sharedUserInfo) return;

        F(bool, sharedUserInfo + 0x340) = true;

        sharedMainManager = F(ptr, libmain + O(0x4dde3e0));
        if (!sharedMainManager) return;

        sharedMenuManager = F(ptr, libmain + O(0x4dfe838));
        if (!sharedMenuManager) return;

        MainStateManager mainStateManager = sharedMainManager.mStateManager;
        if (!mainStateManager) return;
        if (!mainStateManager.isInGame()) {
        if (persistent_bool[O("bAutoQueue")]) {
            if (!sharedMenuManager.isInQueue()) DrawAutoQueue();
        } return;
        }

        auto visualCue = sharedGameManager.mVisualCue();

        Ball::Classification myclass = sharedGameManager.getPlayerClassification();

        Table table = sharedGameManager.mTable;
        if (!table) return;

        auto tableProperties = table.mTableProperties();
        if (!tableProperties) return;

        auto& pockets = tableProperties.mPockets();

        if (persistent_bool[O("bESP_DrawPockets")]) {
            for (int i = 0; i < 6; i++) {
                auto screenPos = WorldToScreen(pockets[i]);
                draw->AddCircle(ImVec2(screenPos.x, screenPos.y), 40, WHITE, 0, 3.f);
            }
        }

        GameStateManager gameStateManager = sharedGameManager.mStateManager;
        if (!gameStateManager) return;

        if (persistent_bool[O("bAutoPlay")]) AutoPlay::Update();

        auto stateId = gameStateManager.getCurrentStateId();
        if (stateId == 4) gPrediction->determineShotResult(false);
        if (stateId == 6 || stateId == 7 || stateId == 8) return;

        if (persistent_bool[O("bESP_DrawPocketsShotState")]) {
            for (int i = 0; i < 6; i++) {
                if (Prediction::pocketStatus[i]) {
                    auto screenPos = WorldToScreen(pockets[i]);
                    draw->AddCircle(ImVec2(screenPos.x, screenPos.y), 40, GREEN, 0, 5.f);
                }
            }
        }

        if (persistent_bool[O("bESP_DrawPredictionLine")]) {
            for (int i = 0; i < gPrediction->guiData.ballsCount; i++) {
                auto& ball = gPrediction->guiData.balls[i];

                if (ball.initialPosition != ball.predictedPosition) {
                    ImVec2 lastPos{};
                    for (int j = 1; j < ball.positions.size(); j++) {
                        auto point = WorldToScreen(ball.positions[j]);
                        if (lastPos.x || lastPos.y) draw->AddLine(lastPos, point, colors[i], 10.f);
                        lastPos = point;
                    }
                }
            }
        }

        if (persistent_bool[O("bESP_DrawPredictionLine")]) {
            for (int i = 0; i < gPrediction->guiData.ballsCount; i++) {
                auto& ball = gPrediction->guiData.balls[i];

                if (ball.initialPosition != ball.predictedPosition) {
                    draw->AddCircle(WorldToScreen(ball.initialPosition), 20, colors[i], 0, 6.f);
                    draw->AddCircleFilled(WorldToScreen(ball.predictedPosition), 20, colors[i]);
                }
            }
        }
    }
}

#include "ButtonClicker.h"

static void DrawSidebar(float sidebarW, float winH) {
    ImDrawList* dl = GetWindowDrawList();
    ImVec2 winPos = GetWindowPos();
    
    DrawGradientRect(dl, winPos, ImVec2(winPos.x + sidebarW, winPos.y + winH), IM_COL32(22, 22, 28, 255), IM_COL32(28, 28, 35, 255), false);
    dl->AddLine(ImVec2(winPos.x + sidebarW, winPos.y), ImVec2(winPos.x + sidebarW, winPos.y + winH), IM_COL32(55, 55, 65, 255), 1.0f);
    
    SetCursorPos(ImVec2(0, 25));
    
    BeginGroup();
    
    Dummy(ImVec2(sidebarW, 5));
    SetCursorPosX(25);
    
    PushStyleColor(ImGuiCol_Text, ImVec4(0.4f, 0.75f, 1.0f, 1.0f));
    SetWindowFontScale(1.2f);
    Text(O("GLASS"));
    SetWindowFontScale(1.0f);
    PopStyleColor();
    
    SetCursorPosX(25);
    TextColored(ImVec4(0.55f, 0.55f, 0.6f, 1.0f), O("Engine v1.0"));
    
    Dummy(ImVec2(sidebarW, 35));
    
    SetCursorPosX(15);
    if (SidebarButton(O("ESP"), O(">"), g_menu.currentTab == 0, sidebarW)) g_menu.currentTab = 0;
    
    Dummy(ImVec2(0, 5));
    SetCursorPosX(15);
    if (SidebarButton(O("Auto Play"), O(">"), g_menu.currentTab == 1, sidebarW)) g_menu.currentTab = 1;
    
    Dummy(ImVec2(0, 5));
    SetCursorPosX(15);
    if (SidebarButton(O("Auto Queue"), O(">"), g_menu.currentTab == 2, sidebarW)) g_menu.currentTab = 2;
    
    EndGroup();
}

static void DrawContentArea(float sidebarW, float winW, float winH) {
    bool need_save = false;
    
    ImDrawList* dl = GetWindowDrawList();
    ImVec2 winPos = GetWindowPos();
    
    DrawGradientRect(dl, ImVec2(winPos.x + sidebarW, winPos.y), ImVec2(winPos.x + winW, winPos.y + 65), IM_COL32(30, 30, 38, 255), IM_COL32(35, 35, 42, 255), false);
    dl->AddLine(ImVec2(winPos.x + sidebarW, winPos.y + 65), ImVec2(winPos.x + winW, winPos.y + 65), IM_COL32(50, 50, 60, 255), 1.0f);
    
    const char* tabTitles[] = { "ESP Settings", "Auto Play", "Auto Queue" };
    
    SetCursorPos(ImVec2(sidebarW + 25, 22));
    SetWindowFontScale(1.15f);
    TextColored(ImVec4(1.0f, 1.0f, 1.0f, 1.0f), "%s", tabTitles[g_menu.currentTab]);
    SetWindowFontScale(1.0f);
    
    SetCursorPos(ImVec2(sidebarW + 15, 80));
    
    PushStyleColor(ImGuiCol_ChildBg, ImVec4(0, 0, 0, 0));
    PushStyleVar(ImGuiStyleVar_ScrollbarSize, 0.0f);
    BeginChild(O("##ContentArea"), ImVec2(winW - sidebarW - 30, winH - 95), false, ImGuiWindowFlags_NoScrollbar);
    
    switch (g_menu.currentTab) {
        case 0: {
            Dummy(ImVec2(0, 10));
            need_save |= ToggleSwitch(O("Draw Prediction Lines"), &persistent_bool[O("bESP_DrawPredictionLine")]);
            need_save |= ToggleSwitch(O("Draw Pockets"), &persistent_bool[O("bESP_DrawPockets")]);
            need_save |= ToggleSwitch(O("Draw Shot State"), &persistent_bool[O("bESP_DrawPocketsShotState")]);
            break;
        }
        
        case 1: {
            Dummy(ImVec2(0, 10));
            need_save |= ToggleSwitch(O("Enable Auto Play"), &persistent_bool[O("bAutoPlay")]);
            
            Dummy(ImVec2(0, 20));
            TextColored(ImVec4(0.5f, 0.5f, 0.55f, 1.0f), O("Auto play will automatically"));
            TextColored(ImVec4(0.5f, 0.5f, 0.55f, 1.0f), O("aim and shoot for you"));
            break;
        }
        
        case 2: {
            Dummy(ImVec2(0, 10));
            need_save |= ToggleSwitch(O("Enable Auto Queue"), &persistent_bool[O("bAutoQueue")]);
            Dummy(ImVec2(0, 20));
            
            TextColored(ImVec4(0.75f, 0.75f, 0.8f, 1.0f), O("Mode"));
            Dummy(ImVec2(0, 8));
            PushStyleVar(ImGuiStyleVar_FrameRounding, 10.0f);
            PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(15, 12));
            PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.12f, 0.12f, 0.15f, 1.0f));
            PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0.16f, 0.16f, 0.20f, 1.0f));
            SetNextItemWidth(GetContentRegionAvail().x);
            need_save |= Combo("##mode", &persistent_int["iAutoQueue_Mode"], "Last Selected\0Smart\0");
            PopStyleColor(2);
            PopStyleVar(2);
            
            if (persistent_int["iAutoQueue_Mode"] == 1) {
                Dummy(ImVec2(0, 15));
                TextColored(ImVec4(0.75f, 0.75f, 0.8f, 1.0f), O("Bet Percent"));
                Dummy(ImVec2(0, 8));
                PushStyleVar(ImGuiStyleVar_FrameRounding, 10.0f);
                PushStyleVar(ImGuiStyleVar_GrabRounding, 10.0f);
                PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.12f, 0.12f, 0.15f, 1.0f));
                PushStyleColor(ImGuiCol_SliderGrab, ImVec4(0.3f, 0.6f, 0.95f, 1.0f));
                PushStyleColor(ImGuiCol_SliderGrabActive, ImVec4(0.4f, 0.7f, 1.0f, 1.0f));
                SetNextItemWidth(GetContentRegionAvail().x);
                need_save |= SliderInt("##betpercent", &persistent_int["iAutoQueue_BetPercent"], 1, 100, "%d%%");
                PopStyleColor(3);
                PopStyleVar(2);
            }
            
            Dummy(ImVec2(0, 25));
            TextColored(ImVec4(0.5f, 0.5f, 0.55f, 1.0f), O("You will be auto queued to"));
            TextColored(ImVec4(0.5f, 0.5f, 0.55f, 1.0f), O("the last game mode you played"));
            break;
        }
    }
    
    if (need_save) save_persistence();
    
    EndChild();
    PopStyleVar();
    PopStyleColor();
}

INLINE void DrawMenu(ImGuiIO& io) {
    if (!g_Token.empty() && !g_Auth.empty() && g_Token == g_Auth) {
        if (is_segv_handler_active()) {
            jump_buffer_active = 1;
            if (!sigsetjmp(jump_buffer, 1)) DrawESP(GetBackgroundDrawList());
            jump_buffer_active = 0;
        }

        float targetAlpha = g_menu.isOpen ? 1.0f : 0.0f;
        if (g_menu.isOpen) {
            g_menu.menuAlpha += (1.0f - g_menu.menuAlpha) * io.DeltaTime * 12.0f;
        } else {
            g_menu.menuAlpha = 0.0f;
        }

        if (g_menu.menuAlpha > 0.01f) {
            float winW = 800.0f;
            float winH = 580.0f;
            
            SetNextWindowSize(ImVec2(winW, winH), ImGuiCond_Always);
            SetNextWindowPos(ImVec2(Width / 2.0f, Height / 2.0f), ImGuiCond_FirstUseEver, ImVec2(0.5f, 0.5f));
            
            PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.13f, 0.13f, 0.16f, g_menu.menuAlpha));
            PushStyleVar(ImGuiStyleVar_WindowRounding, 16.0f);
            PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
            PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
            PushStyleVar(ImGuiStyleVar_Alpha, g_menu.menuAlpha);
            
            ImGuiWindowFlags winFlags = ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;
            
            if (Begin(O("##MainMenu"), &g_menu.isOpen, winFlags)) {
                ImDrawList* dl = GetWindowDrawList();
                ImVec2 winPos = GetWindowPos();
                
                dl->AddRect(winPos, ImVec2(winPos.x + winW, winPos.y + winH), IM_COL32(60, 60, 70, (int)(150 * g_menu.menuAlpha)), 16.0f, 0, 1.5f);
                
                DrawSidebar(g_menu.sidebarWidth, winH);
                DrawContentArea(g_menu.sidebarWidth, winW, winH);
            }
            End();
            
            PopStyleVar(4);
            PopStyleColor();
        }
    }
}

static void DrawFloatingButton(ImGuiIO& io) {
    static ImVec2 buttonPos = ImVec2(80, 60);
    static bool isDragging = false;
    static float hoverAnim = 0.0f;
    
    float buttonRadius = 38.0f;
    float buttonSize = buttonRadius * 2.0f;
    float textWidth = 140.0f;
    float totalWidth = buttonSize + textWidth + 15.0f;
    float totalHeight = buttonSize + 4.0f;
    
    bool isHovered = false;
    
    SetNextWindowPos(buttonPos, ImGuiCond_Always);
    SetNextWindowSize(ImVec2(totalWidth, totalHeight), ImGuiCond_Always);
    PushStyleColor(ImGuiCol_WindowBg, ImVec4(0, 0, 0, 0));
    PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    
    if (Begin(O("##FloatBtn"), nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings)) {
        ImDrawList* dl = GetWindowDrawList();
        
        ImVec2 center = ImVec2(buttonPos.x + buttonRadius + 2, buttonPos.y + buttonRadius + 2);
        
        SetCursorPos(ImVec2(0, 0));
        InvisibleButton(O("##FloatBtnHit"), ImVec2(totalWidth, totalHeight));
        isHovered = IsItemHovered();
        
        float targetHover = isHovered ? 1.0f : 0.0f;
        hoverAnim += (targetHover - hoverAnim) * io.DeltaTime * 10.0f;
        
        float currentRadius = buttonRadius + hoverAnim * 4.0f;
        
        dl->AddCircleFilled(ImVec2(center.x + 2, center.y + 3), currentRadius, IM_COL32(0, 0, 0, 60), 32);
        dl->AddCircleFilled(center, currentRadius, IM_COL32(30, 85, 160, 255), 32);
        dl->AddCircleFilled(center, currentRadius - 4, IM_COL32(40, 100, 180, 255), 32);
        dl->AddCircle(center, currentRadius, IM_COL32(70, 150, 230, (int)(200 + 55 * hoverAnim)), 32, 2.5f);
        
        float iconSize = 12.0f;
        ImU32 iconColor = IM_COL32(255, 255, 255, 255);
        
        if (g_menu.isOpen) {
            dl->AddLine(ImVec2(center.x - iconSize, center.y - iconSize), ImVec2(center.x + iconSize, center.y + iconSize), iconColor, 3.5f);
            dl->AddLine(ImVec2(center.x + iconSize, center.y - iconSize), ImVec2(center.x - iconSize, center.y + iconSize), iconColor, 3.5f);
        } else {
            float barW = 14.0f;
            float barH = 3.0f;
            float gap = 6.0f;
            dl->AddRectFilled(ImVec2(center.x - barW, center.y - gap - barH), ImVec2(center.x + barW, center.y - gap), iconColor, 2.0f);
            dl->AddRectFilled(ImVec2(center.x - barW, center.y - barH * 0.5f), ImVec2(center.x + barW, center.y + barH * 0.5f), iconColor, 2.0f);
            dl->AddRectFilled(ImVec2(center.x - barW, center.y + gap), ImVec2(center.x + barW, center.y + gap + barH), iconColor, 2.0f);
        }
        
        float textX = buttonPos.x + buttonSize + 12.0f;
        float textY = buttonPos.y + (totalHeight - 38.0f) * 0.5f;
        dl->AddText(ImVec2(textX, textY), IM_COL32(70, 160, 255, 255), O("Glass"));
        dl->AddText(ImVec2(textX, textY + 24.0f), IM_COL32(180, 180, 190, 255), O("Engine"));
        
        if (IsItemActive() && IsMouseDragging(0)) {
            isDragging = true;
            buttonPos.x += io.MouseDelta.x;
            buttonPos.y += io.MouseDelta.y;
            buttonPos.x = ImClamp(buttonPos.x, 0.0f, (float)Width - totalWidth);
            buttonPos.y = ImClamp(buttonPos.y, 0.0f, (float)Height - totalHeight);
        }
        
        if (IsItemHovered() && IsMouseReleased(0) && !isDragging) {
            g_menu.isOpen = !g_menu.isOpen;
        }
        
        if (!IsItemActive()) isDragging = false;
    }
    End();
    
    PopStyleVar(2);
    PopStyleColor();
}


static bool first_time = true;
INLINE void DrawLogin(ImGuiIO& io) {
    if (logged_in) return DrawMenu(io);

    SetNextWindowPos(ImVec2(0, 0));
    SetNextWindowSize(io.DisplaySize);
    PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.04f, 0.04f, 0.06f, 0.96f));
    Begin(O("##Overlay"), nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoInputs | ImGuiWindowFlags_NoBringToFrontOnFocus);
    PopStyleColor();

    float cardW = 580;
    float cardH = 420;

    SetNextWindowSize(ImVec2(cardW, cardH), ImGuiCond_Always);
    SetNextWindowPos(ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f), ImGuiCond_Always, ImVec2(0.5f, 0.5f));

    PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.11f, 0.11f, 0.14f, 1.0f));
    PushStyleVar(ImGuiStyleVar_WindowRounding, 20.0f);
    PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);

    Begin(O("##LoginCard"), nullptr, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoScrollbar);

    ImDrawList* dl = GetWindowDrawList();
    ImVec2 winPos = GetWindowPos();
    
    DrawGradientRect(dl, winPos, ImVec2(winPos.x + cardW, winPos.y + 110), IM_COL32(35, 95, 170, 255), IM_COL32(55, 125, 200, 255), true);
    dl->AddRectFilled(winPos, ImVec2(winPos.x + cardW, winPos.y + 20), IM_COL32(35, 95, 170, 255), 20.0f, ImDrawFlags_RoundCornersTop);

    SetWindowFontScale(1.4f);
    ImVec2 titleSize = CalcTextSize("GLASS ENGINE");
    dl->AddText(ImVec2(winPos.x + (cardW - titleSize.x) * 0.5f, winPos.y + 30), IM_COL32(255, 255, 255, 255), "GLASS ENGINE");
    SetWindowFontScale(1.0f);
    
    ImVec2 subSize = CalcTextSize("Premium 8 Ball Pool Mod");
    dl->AddText(ImVec2(winPos.x + (cardW - subSize.x) * 0.5f, winPos.y + 70), IM_COL32(200, 220, 255, 200), "Premium 8 Ball Pool Mod");

    SetCursorPosY(130);

    if (!ERROR_MESSAGE.empty()) {
        SetCursorPosX(30);
        PushTextWrapPos(cardW - 30);
        TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "%s", ERROR_MESSAGE.c_str());
        PopTextWrapPos();
        Dummy(ImVec2(0, 15));
    }

    if (is_logging_in) {
        SetCursorPosY(180);
        
        static float spinner_angle = 0.0f;
        spinner_angle += io.DeltaTime * 5.0f;

        float spinner_size = 40.0f;
        ImVec2 spinnerCenter = ImVec2(winPos.x + cardW * 0.5f, winPos.y + 220);

        for (int i = 0; i < 12; i++) {
            float angle = spinner_angle + (i * PI * 2.0f / 12.0f);
            float alpha = (float)(12 - i) / 12.0f;
            ImVec2 dotPos = ImVec2(
                spinnerCenter.x + cosf(angle) * spinner_size,
                spinnerCenter.y + sinf(angle) * spinner_size
            );
            dl->AddCircleFilled(dotPos, 6.0f, IM_COL32(100, 180, 255, (int)(alpha * 255)));
        }

        ImVec2 loadingSize = CalcTextSize("Authenticating...");
        SetCursorPosX((cardW - loadingSize.x) * 0.5f);
        SetCursorPosY(290);
        TextColored(ImVec4(0.6f, 0.6f, 0.65f, 1.0f), "Authenticating...");
    } else {
        SetCursorPosY(160);
        
        ImVec2 infoSize = CalcTextSize("Copy your license key and tap login");
        SetCursorPosX((cardW - infoSize.x) * 0.5f);
        TextColored(ImVec4(0.55f, 0.55f, 0.6f, 1.0f), "Copy your license key and tap login");
        
        Dummy(ImVec2(0, 50));
        
        bool AutoLogin = first_time && !persistent_string["key"].empty();
        
        SetCursorPosX(40);
        PushStyleColor(ImGuiCol_Button, ImVec4(0.20f, 0.50f, 0.80f, 1.0f));
        PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.25f, 0.58f, 0.90f, 1.0f));
        PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.18f, 0.45f, 0.72f, 1.0f));
        PushStyleVar(ImGuiStyleVar_FrameRounding, 14.0f);
        
        if (AutoLogin || Button("LOGIN WITH CLIPBOARD", ImVec2(cardW - 80, 65))) {
            JNIEnv* env;
            jint getEnvResult = VM->GetEnv((void**)&env, JNI_VERSION_1_6);
            if (getEnvResult == JNI_EDETACHED) {
                if (VM->AttachCurrentThread(&env, nullptr) != 0) ERROR_MESSAGE = O("Failed to attach thread to JVM");
            } else if (getEnvResult != JNI_OK) {
                ERROR_MESSAGE = O("Failed to get JNIEnv");
            } else {
                std::thread([](std::string androidId, std::string key) {
                    Login(androidId, key);
                }, getAndroidID(env), AutoLogin ? persistent_string["key"] : getClipboard(env)).detach();
            }

            first_time = false;
        }
        
        PopStyleVar();
        PopStyleColor(3);
        
        Dummy(ImVec2(0, 35));
        
        ImVec2 helpSize = CalcTextSize("Your key will be read from clipboard");
        SetCursorPosX((cardW - helpSize.x) * 0.5f);
        TextColored(ImVec4(0.42f, 0.42f, 0.48f, 1.0f), "Your key will be read from clipboard");
    }

    End();
    PopStyleVar(3);
    PopStyleColor();
    
    End();
}


INLINE void SetupImgui() {
    PACKAGE_NAME = string(getcmdline());

    ImGui::CreateContext();

    auto& style = ImGui::GetStyle();
    auto& io = ImGui::GetIO();

    io.ConfigFlags |= ImGuiConfigFlags_IsTouchScreen;

    switch_theme(current_theme);

    load_persistence();
    load_imgui_style();

    static string INI_PATH = O("/data/user_de/0/") + PACKAGE_NAME + O("/no_backup/.ini");
    io.IniFilename = persistent_bool["bImguiAutoSave"] ? INI_PATH.c_str() : nullptr;
    io.ConfigWindowsMoveFromTitleBarOnly = persistent_bool["bMoveOnlyWithTitleBar"];

    ImFontConfig font_cfg;
    font_cfg.SizePixels = persistent_float["fFontScale"];
    io.Fonts->AddFontDefault(&font_cfg);

    ImGui_ImplAndroid_Init();
    ImGui_ImplOpenGL3_Init(O("#version 300 es"));

    bImguiSetup = true;
}

DEFINES(EGLBoolean, Draw, EGLDisplay dpy, EGLSurface surface) {
    eglQuerySurface(dpy, surface, EGL_WIDTH, &Width);
    eglQuerySurface(dpy, surface, EGL_HEIGHT, &Height);

    if (Width <= 0 || Height <= 0) return _Draw(dpy, surface);

    screenCenter = Vector2(Width / 2, Height / 2);

    if (!bImguiSetup) SetupImgui();

    ImGuiIO& io = ImGui::GetIO();

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplAndroid_NewFrame(Width, Height);
    ImGui::NewFrame();

    if (!is_segv_handler_active()) setup_global_segv_handler();
    if (!g_Token.empty() && !g_Auth.empty() && g_Token == g_Auth) {
        DrawFloatingButton(io);
        DrawMenu(io);
    } else {
        DrawLogin(io);
    }
    ImGui::EndFrame();
    ImGui::Render();
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    ImGui_ClearHoverEffect();

    return _Draw(dpy, surface);
}

void __IMGUI__() {
    create_directory_recursive(CONC(O("/data/user_de/0/"), PACKAGE_NAME.c_str(), O("/no_backup")));
}
