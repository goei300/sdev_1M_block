#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void cutFile(FILE* f) {
    FILE* wf = fopen("./top-1m_r.txt","w");
    if (wf == NULL) {
        printf("Error opening write file.\n");
        return;
    }

    char str[100];
    while(fgets(str, sizeof(str), f) != NULL) {
        char *token = strtok(str, ",");
        token = strtok(NULL, "\n");
        if (token != NULL) {
            char str2[105]; // assume..
            sprintf(str2, "www.%s", token); // concatenate "www." and token into str2 for compare real site name
            fputs(str2, wf);
            fputs("\n", wf); 
        }
    }
    fclose(wf);
}

int compare(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

void sortSites() {
    FILE* f = fopen("./top-1m_r.txt", "r");
    if (f == NULL) {
        printf("Error opening file for sorting.\n");
        return;
    }

    char *sites[762564];  // 762524 sites
    char buffer[105];
    int count = 0;

    while (fgets(buffer, sizeof(buffer), f) && count < 700000) {
        sites[count] = strdup(buffer);
        count++;
    }
    fclose(f);

    qsort(sites, count, sizeof(char *), compare);

    FILE* wf = fopen("./top-1m_r.txt", "w");
    if (wf == NULL) {
        printf("Error opening write file for sorted sites.\n");
        return;
    }
    for (int i = 0; i < count; i++) {
        fputs(sites[i], wf);
        free(sites[i]);
    }
    fclose(wf);
}

int main() {
    FILE *f = fopen("./top-1m.txt", "r");
    if (f == NULL) {
        printf("Error opening file.\n");
        return 1;
    }
    cutFile(f);
    fclose(f);

    sortSites();

    return 0;
}